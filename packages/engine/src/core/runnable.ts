import { PromisePool } from "@supercharge/promise-pool";
import { batchingToposort } from "batching-toposort-ts";
import { type SDK } from "caido:plugin";
import {
  type Request,
  type RequestSpec,
  type RequestSpecRaw,
  type Response,
} from "caido:utils";
import mitt from "mitt";

import {
  ScanRunnableError,
  ScanRunnableErrorCode,
  ScanRunnableInterruptedError,
  ScanRuntimeError,
} from "../core/errors";
import { type Check, type CheckOutput } from "../types/check";
import { type Finding } from "../types/finding";
import {
  type CheckExecutionRecord,
  type ExecutionHistory,
  type InterruptReason,
  type RuntimeContext,
  type ScanConfig,
  type ScanEstimateResult,
  type ScanEvents,
  type ScanResult,
  type ScanRunnable,
  type ScanTarget,
  type StepExecutionRecord,
} from "../types/runner";
import { parseHtmlFromString } from "../utils/html/parser";
import { type ParsedHtml } from "../utils/html/types";

import { createTaskExecutor } from "./execution";
import { createRequestQueue } from "./request-queue";

export const createRunnable = ({
  sdk,
  checks,
  config,
}: {
  sdk: SDK;
  checks: Check[];
  config: ScanConfig;
}): ScanRunnable => {
  const { on, emit } = mitt<ScanEvents>();
  const batches = getCheckBatches(checks);
  const findings: Map<string, Finding[]> = new Map();
  const dependencies = new Map<string, CheckOutput>();
  const htmlCache = new Map<string, ParsedHtml>();
  let dedupeKeys = new Map<string, Set<string>>();
  let interruptReason: InterruptReason | undefined;
  let hasRun = false;

  const executionHistory: ExecutionHistory = [];
  const activeCheckRecords = new Map<
    string,
    {
      checkId: string;
      targetRequestId: string;
      steps: StepExecutionRecord[];
    }
  >();

  const requestQueue = createRequestQueue({
    sdk,
    config,
    emit,
    getInterruptReason: () => interruptReason,
  });

  const recordStepExecution = (
    checkId: string,
    targetRequestId: string,
    record: StepExecutionRecord,
  ) => {
    const key = `${checkId}-${targetRequestId}`;
    const activeRecord = activeCheckRecords.get(key);
    if (activeRecord) {
      activeRecord.steps.push(record);
    }
  };

  const createDedupeKeysSnapshot = (): Map<string, Set<string>> => {
    const snapshot = new Map<string, Set<string>>();
    for (const [checkId, keySet] of dedupeKeys) {
      snapshot.set(checkId, new Set(keySet));
    }
    return snapshot;
  };

  const externalDedupeKeys = (externalDedupeKeys: Map<string, Set<string>>) => {
    if (hasRun) {
      throw new ScanRunnableError(
        "Cannot set dedupe keys after scan has started",
        ScanRunnableErrorCode.SCAN_ALREADY_RUNNING,
      );
    }
    dedupeKeys = externalDedupeKeys;
  };

  const isCheckApplicable = (
    check: Check,
    context: RuntimeContext,
    targetDedupeKeys: Map<string, Set<string>> = dedupeKeys,
  ): boolean => {
    if (
      !check.metadata.severities.some((s) =>
        context.config.severities.includes(s),
      )
    ) {
      return false;
    }

    if (
      check.metadata.minAggressivity !== undefined &&
      check.metadata.minAggressivity > context.config.aggressivity
    ) {
      return false;
    }

    if (check.when !== undefined && !check.when(context.target)) {
      return false;
    }

    if (check.dedupeKey !== undefined) {
      const checkId = check.metadata.id;
      const key = check.dedupeKey(context.target);

      let checkCache = targetDedupeKeys.get(checkId);
      if (checkCache === undefined) {
        checkCache = new Set<string>();
        targetDedupeKeys.set(checkId, checkCache);
      }

      if (checkCache.has(key)) {
        return false;
      }

      checkCache.add(key);
    }

    return true;
  };

  const createRuntimeContext = (
    target: ScanTarget,
    sdk: SDK,
  ): RuntimeContext => {
    return {
      target,
      config,
      sdk,
      runtime: {
        html: {
          parse: async (requestID: string) => {
            const cachedHtml = htmlCache.get(requestID);
            if (cachedHtml) {
              return cachedHtml;
            }

            const request = await sdk.requests.get(requestID);
            if (!request) {
              throw new ScanRunnableError(
                `Request ${requestID} not found`,
                ScanRunnableErrorCode.REQUEST_NOT_FOUND,
              );
            }

            if (request.response === undefined) {
              throw new ScanRunnableError(
                `Response for request ${requestID} not found`,
                ScanRunnableErrorCode.REQUEST_NOT_FOUND,
              );
            }

            const body = request.response.getBody();
            if (body === undefined) {
              throw new ScanRunnableError(
                `Body for request ${requestID} not found`,
                ScanRunnableErrorCode.REQUEST_NOT_FOUND,
              );
            }

            const parsedHtml = parseHtmlFromString(body.toText());
            htmlCache.set(requestID, parsedHtml);
            return parsedHtml;
          },
        },
        dependencies: {
          get: (key: string) => {
            return dependencies.get(key);
          },
        },
      },
    };
  };

  const createWrappedSdk = (checkID: string, targetRequestID: string): SDK => {
    return {
      ...sdk,
      requests: {
        // ...sdk.requests didn't work :(
        inScope: (request: Request | RequestSpec) => {
          return sdk.requests.inScope(request);
        },
        query: () => {
          return sdk.requests.query();
        },
        matches: (filter: string, request: Request, response?: Response) => {
          return sdk.requests.matches(filter, request, response);
        },
        get: async (id: string) => {
          return sdk.requests.get(id);
        },
        send: async (request: RequestSpec | RequestSpecRaw) => {
          const pendingRequestID = Math.random().toString(36).substring(2, 15);

          emit("scan:request-pending", {
            pendingRequestID,
            targetRequestID,
            checkID,
          });

          return requestQueue.enqueue(
            request,
            pendingRequestID,
            targetRequestID,
            checkID,
          );
        },
      } as unknown as SDK["requests"],
    } as SDK;
  };

  const processBatch = async (
    batch: Check[],
    context: RuntimeContext,
  ): Promise<void> => {
    const tasks = batch
      .filter((check) => isCheckApplicable(check, context))
      .map((check) => {
        const wrappedSdk = createWrappedSdk(
          check.metadata.id,
          context.target.request.getId(),
        );
        const taskContext = {
          ...context,
          sdk: wrappedSdk,
          __v2Context: {
            wrappedSdk,
            getInterrupted: () => interruptReason !== undefined,
          },
        };
        return check.create(taskContext);
      });

    const { errors } = await PromisePool.for(tasks)
      .withConcurrency(context.config.concurrentChecks)
      .withTaskTimeout(context.config.checkTimeout * 1000)
      .handleError((error, _, pool) => {
        if (error instanceof ScanRunnableInterruptedError) {
          pool.stop();
          return;
        }

        throw error;
      })
      .onTaskFinished((task) => {
        emit("scan:check-finished", {
          checkID: task.metadata.id,
          targetRequestID: context.target.request.getId(),
        });
      })
      .onTaskStarted((task) => {
        const key = `${task.metadata.id}-${context.target.request.getId()}`;
        activeCheckRecords.set(key, {
          checkId: task.metadata.id,
          targetRequestId: context.target.request.getId(),
          steps: [],
        });
        emit("scan:check-started", {
          checkID: task.metadata.id,
          targetRequestID: context.target.request.getId(),
        });
      })
      .process(async (task) => {
        if (task.metadata.skipIfFoundBy) {
          const existingFindings = findings.get(task.metadata.id) || [];
          if (existingFindings.length > 0) {
            return;
          }
        }

        const taskExecutor = createTaskExecutor({
          emit,
          getInterruptReason: () => interruptReason,
          recordStepExecution: (record: StepExecutionRecord) => {
            recordStepExecution(
              task.metadata.id,
              context.target.request.getId(),
              record,
            );
          },
        });
        const result = await taskExecutor.tickUntilDone(task);
        if (result.findings) {
          const existingFindings = findings.get(task.metadata.id) || [];
          findings.set(task.metadata.id, [
            ...existingFindings,
            ...result.findings,
          ]);
        }

        if (result.status === "done") {
          dependencies.set(task.metadata.id, result.output);
          const key = `${task.metadata.id}-${context.target.request.getId()}`;
          const activeRecord = activeCheckRecords.get(key);

          if (activeRecord) {
            const checkRecord: CheckExecutionRecord = {
              checkId: activeRecord.checkId,
              targetRequestId: activeRecord.targetRequestId,
              steps: activeRecord.steps,
              status: "completed",
              finalOutput: result.output,
            };

            executionHistory.push(checkRecord);
            activeCheckRecords.delete(key);
          }
        }

        if (result.status === "failed") {
          const key = `${task.metadata.id}-${context.target.request.getId()}`;
          const activeRecord = activeCheckRecords.get(key);

          if (activeRecord) {
            const checkRecord: CheckExecutionRecord = {
              checkId: activeRecord.checkId,
              targetRequestId: activeRecord.targetRequestId,
              steps: activeRecord.steps,
              status: "failed",
              error: {
                code: result.errorCode,
                message: result.errorMessage,
              },
            };

            executionHistory.push(checkRecord);
            activeCheckRecords.delete(key);
          }
          emit("scan:check-failed", {
            checkID: task.metadata.id,
            targetRequestID: context.target.request.getId(),
            errorCode: result.errorCode,
            errorMessage: result.errorMessage,
          });
        }

        return result;
      });

    if (errors.length > 0) {
      throw new ScanRuntimeError(errors);
    }
  };

  return {
    run: async (requestIDs: string[]): Promise<ScanResult> => {
      if (hasRun) {
        return { kind: "Error", error: "Scan is already running" };
      }

      const runScan = async (): Promise<ScanResult> => {
        try {
          hasRun = true;
          emit("scan:started", {});

          const processTarget = async (requestID: string): Promise<void> => {
            const target = await sdk.requests.get(requestID);
            if (target === undefined) {
              throw new ScanRunnableError(
                `Request ${requestID} not found`,
                ScanRunnableErrorCode.REQUEST_NOT_FOUND,
              );
            }

            const context = createRuntimeContext(
              {
                request: target.request,
                response: target.response,
              },
              sdk,
            );

            for (const batch of batches) {
              if (interruptReason) {
                throw new ScanRunnableInterruptedError(interruptReason);
              }

              await processBatch(batch, context);
            }
          };

          const { errors } = await PromisePool.for(requestIDs)
            .withConcurrency(config.concurrentTargets)
            .handleError((error, _, pool) => {
              if (error instanceof ScanRunnableInterruptedError) {
                pool.stop();
                return;
              }
              throw error;
            })
            .process(processTarget);

          if (errors.length > 0) {
            throw new ScanRuntimeError(errors);
          }

          return {
            kind: "Finished",
            findings: Array.from(findings.values()).flat(),
          };
        } catch (error) {
          if (error instanceof ScanRunnableInterruptedError) {
            emit("scan:interrupted", { reason: error.reason });
            return {
              kind: "Interrupted",
              reason: error.reason,
              findings: Array.from(findings.values()).flat(),
            };
          }

          return {
            kind: "Error",
            error: error instanceof Error ? error.message : "Unknown error",
          };
        } finally {
          emit("scan:finished", {});
        }
      };

      if (config.scanTimeout > 0) {
        const timeoutPromise = new Promise<ScanResult>((resolve) => {
          setTimeout(() => {
            if (!interruptReason) {
              interruptReason = "Timeout";
            }
            resolve({
              kind: "Interrupted",
              reason: "Timeout",
              findings: Array.from(findings.values()).flat(),
            });
          }, config.scanTimeout * 1000);
        });

        return Promise.race([runScan(), timeoutPromise]);
      } else {
        return runScan();
      }
    },
    estimate: async (requestIDs: string[]): Promise<ScanEstimateResult> => {
      let checksTotal = 0;
      const snapshotDedupeKeys = createDedupeKeysSnapshot();
      for (const requestID of requestIDs) {
        const target = await sdk.requests.get(requestID);
        if (target === undefined) {
          return { kind: "Error", error: `Request ${requestID} not found` };
        }

        const context = createRuntimeContext(
          {
            request: target.request,
            response: target.response,
          },
          sdk,
        );

        const tasks = batches.map((batch) =>
          batch.filter((check) =>
            isCheckApplicable(check, context, snapshotDedupeKeys),
          ),
        );

        checksTotal += tasks.flat().length;
      }

      return { kind: "Ok", checksTotal };
    },
    cancel: async (reason) => {
      if (interruptReason || !hasRun) {
        return;
      }

      interruptReason = reason;
      await new Promise<void>((resolve) => {
        on("scan:interrupted", () => resolve());
      });
    },
    externalDedupeKeys,
    on: (event, callback) => on(event, callback),
    emit: (event, data) => emit(event, data),
    getExecutionHistory: () => [...executionHistory],
  };
};

const getCheckBatches = (checks: Check[]): Check[][] => {
  const checkMap = new Map(checks.map((check) => [check.metadata.id, check]));
  const dag: Record<string, string[]> = {};

  for (const check of checks) {
    dag[check.metadata.id] = [];
  }

  for (const check of checks) {
    const dependencies = check.metadata.dependsOn;
    if (dependencies) {
      for (const dependencyId of dependencies) {
        if (!checkMap.has(dependencyId)) {
          throw new Error(
            `Check '${check.metadata.id}' has unknown dependency '${dependencyId}'`,
          );
        }
        if (!dag[dependencyId]) {
          dag[dependencyId] = [];
        }
        dag[dependencyId].push(check.metadata.id);
      }
    }
  }

  const batches = batchingToposort(dag);
  return batches.map((batch) =>
    batch.map((checkId) => {
      const check = checkMap.get(checkId);
      if (!check) {
        throw new Error(`Check '${checkId}' not found in checkMap`);
      }
      return check;
    }),
  );
};
