import { type SDK } from "caido:plugin";
import { type Request } from "caido:utils";
import mitt from "mitt";

import {
  ScanRunnableError,
  ScanRunnableErrorCode,
  ScanRunnableInterruptedError,
  ScanRuntimeError,
} from "../../core/errors";
import {
  type Check,
  type CheckOutput,
  type CheckTask,
} from "../../types/check";
import { type Finding } from "../../types/finding";
import {
  type InterruptReason,
  type RuntimeContext,
  type ScanConfig,
  type ScanEstimateResult,
  type ScanEvents,
  type ScanResult,
  type ScanRunnable,
  type StepExecutionRecord,
} from "../../types/runner";
import { type ParsedHtml } from "../../utils/html/types";
import { createScheduler } from "../../utils/scheduler";
import { createTaskExecutor } from "../execution";
import { createRequestQueue } from "../request-queue";

import { createExecutionHistoryRecorder } from "./history";
import { createRuntimeAccessors } from "./runtime";
import {
  applyCheckApplicability,
  createDedupeKeysSnapshot,
  getCheckBatches,
  isInterruptCancellationError,
  withTimeout,
} from "./utils";

type PendingController = {
  clearPending: (reason: string) => void;
};

const createInterruptController = (
  pendingControllers: Set<PendingController>,
) => {
  let interruptReason: InterruptReason | undefined;

  return {
    getReason: () => interruptReason,
    setReason: (reason: InterruptReason) => {
      if (interruptReason !== undefined) {
        return;
      }

      interruptReason = reason;
      for (const controller of pendingControllers) {
        controller.clearPending(reason);
      }
    },
  };
};

/**
 * Creates a runnable scan from a set of checks and a scan configuration.
 *
 * Most engine consumers use this through `createRegistry().create(...)` and then
 * call `run()` with target request IDs. The returned runnable also gives access to
 * findings, execution history, events, and scan interruption.
 */
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
  const history = createExecutionHistoryRecorder();
  const findings = new Map<string, Finding[]>();
  const dependencies = new Map<string, CheckOutput>();
  const htmlCache = new Map<string, ParsedHtml>();
  let dedupeKeys = new Map<string, Set<string>>();
  let hasRun = false;

  const pendingControllers = new Set<PendingController>();
  const interruptController = createInterruptController(pendingControllers);

  const requestQueue = createRequestQueue({
    sdk,
    config,
    emit,
    getInterruptReason: interruptController.getReason,
  });
  pendingControllers.add(requestQueue);

  const { createRuntimeContext, createWrappedSdk } = createRuntimeAccessors({
    sdk,
    config,
    dependencies,
    htmlCache,
    requestQueue,
    emit,
  });

  const isTargetInScope = (request: Request): boolean => {
    if (config.scopeIDs.length === 0) {
      return true;
    }

    return sdk.requests.inScope(request, config.scopeIDs);
  };

  const externalDedupeKeys = (externalKeys: Map<string, Set<string>>) => {
    if (hasRun) {
      throw new ScanRunnableError(
        "Cannot set dedupe keys after scan has started",
        ScanRunnableErrorCode.SCAN_ALREADY_RUNNING,
      );
    }

    dedupeKeys = externalKeys;
  };

  const isCheckApplicable = (
    check: Check,
    context: RuntimeContext,
    targetDedupeKeys: Map<string, Set<string>> = dedupeKeys,
  ): boolean => {
    return applyCheckApplicability({
      check,
      context,
      dedupeKeys: targetDedupeKeys,
    });
  };

  const recordStepExecution = (
    checkId: string,
    targetRequestId: string,
    record: StepExecutionRecord,
  ) => {
    history.recordStep({
      checkId,
      targetRequestId,
      record,
    });
  };

  const createTaskContext = ({
    check,
    context,
  }: {
    check: Check;
    context: RuntimeContext;
  }) => {
    const wrappedSdk = createWrappedSdk(
      check.metadata.id,
      context.target.request.getId(),
    );

    return {
      ...context,
      sdk: wrappedSdk,
      __v2Context: {
        wrappedSdk,
        getInterrupted: () => interruptController.getReason() !== undefined,
      },
    };
  };

  const addTaskFindings = ({
    checkId,
    taskFindings,
  }: {
    checkId: string;
    taskFindings: Finding[] | undefined;
  }) => {
    if (taskFindings === undefined) {
      return;
    }

    const existingFindings = findings.get(checkId) || [];
    findings.set(checkId, [...existingFindings, ...taskFindings]);
  };

  const shouldSkipTask = (task: CheckTask): boolean => {
    if (task.metadata.skipIfFoundBy === undefined) {
      return false;
    }

    return task.metadata.skipIfFoundBy.some((checkId) => {
      const existingFindings = findings.get(checkId);
      return existingFindings !== undefined && existingFindings.length > 0;
    });
  };

  const recordCheckFailure = ({
    task,
    errorCode,
    errorMessage,
  }: {
    task: CheckTask;
    errorCode: ScanRunnableErrorCode;
    errorMessage: string;
  }) => {
    const targetRequestId = task.getTarget().request.getId();

    history.fail({
      checkId: task.metadata.id,
      targetRequestId,
      errorCode,
      errorMessage,
    });

    emit("scan:check-failed", {
      checkID: task.metadata.id,
      targetRequestID: targetRequestId,
      errorCode,
      errorMessage,
    });
  };

  const executeTask = async ({
    task,
    context,
  }: {
    task: CheckTask;
    context: RuntimeContext;
  }) => {
    const targetRequestId = context.target.request.getId();
    const interruptReason = interruptController.getReason();
    if (interruptReason !== undefined) {
      throw new ScanRunnableInterruptedError(interruptReason);
    }

    history.start({
      checkId: task.metadata.id,
      targetRequestId,
    });
    emit("scan:check-started", {
      checkID: task.metadata.id,
      targetRequestID: targetRequestId,
    });

    try {
      await withTimeout({
        timeoutMs: context.config.checkTimeout * 1000,
        onTimeout: () => {
          recordCheckFailure({
            task,
            errorCode: ScanRunnableErrorCode.RUNTIME_ERROR,
            errorMessage: `Check timed out after ${context.config.checkTimeout} seconds`,
          });
        },
        run: async () => {
          if (shouldSkipTask(task)) {
            history.drop({
              checkId: task.metadata.id,
              targetRequestId,
            });
            return;
          }

          const taskExecutor = createTaskExecutor({
            emit,
            getInterruptReason: interruptController.getReason,
            recordStepExecution: (record) => {
              recordStepExecution(task.metadata.id, targetRequestId, record);
            },
          });

          const result = await taskExecutor.tickUntilDone(task);
          addTaskFindings({
            checkId: task.metadata.id,
            taskFindings: result.findings,
          });

          if (result.status === "done") {
            dependencies.set(task.metadata.id, result.output);
            history.complete({
              checkId: task.metadata.id,
              targetRequestId,
              finalOutput: result.output,
            });
          }

          if (result.status === "failed") {
            recordCheckFailure({
              task,
              errorCode: result.errorCode,
              errorMessage: result.errorMessage,
            });
          }
        },
      });
    } catch (error) {
      if (error instanceof ScanRunnableInterruptedError) {
        throw error;
      }

      if (error instanceof Error && error.message === "timeout") {
        return;
      }

      throw error;
    } finally {
      emit("scan:check-finished", {
        checkID: task.metadata.id,
        targetRequestID: targetRequestId,
      });
    }
  };

  const runTasksWithScheduler = async ({
    scheduler,
    jobs,
  }: {
    scheduler: ReturnType<typeof createScheduler>;
    jobs: Array<() => Promise<void>>;
  }) => {
    pendingControllers.add(scheduler);
    const errors: Error[] = [];

    const jobPromises = jobs.map((job) =>
      scheduler.schedule(job).promise.catch((error: unknown) => {
        if (error instanceof ScanRunnableInterruptedError) {
          return;
        }

        if (
          isInterruptCancellationError({
            interruptReason: interruptController.getReason(),
            error,
          })
        ) {
          return;
        }

        if (error instanceof Error) {
          errors.push(error);
          return;
        }

        errors.push(new Error(String(error)));
      }),
    );

    await Promise.all(jobPromises);
    await scheduler.onIdle();
    pendingControllers.delete(scheduler);

    if (errors.length > 0) {
      throw new ScanRuntimeError(errors);
    }
  };

  const processBatch = async ({
    batch,
    context,
  }: {
    batch: Check[];
    context: RuntimeContext;
  }) => {
    const tasks = batch
      .filter((check) => isCheckApplicable(check, context))
      .map((check) => check.create(createTaskContext({ check, context })));

    const scheduler = createScheduler(context.config.concurrentChecks);
    await runTasksWithScheduler({
      scheduler,
      jobs: tasks.map((task) => {
        return async () => {
          await executeTask({
            task,
            context,
          });
        };
      }),
    });
  };

  const processTarget = async (requestID: string): Promise<void> => {
    const target = await sdk.requests.get(requestID);
    if (target === undefined) {
      throw new ScanRunnableError(
        `Request ${requestID} not found`,
        ScanRunnableErrorCode.REQUEST_NOT_FOUND,
      );
    }
    if (!isTargetInScope(target.request)) {
      return;
    }

    const context = createRuntimeContext(
      {
        request: target.request,
        response: target.response,
      },
      sdk,
    );

    for (const batch of batches) {
      const interruptReason = interruptController.getReason();
      if (interruptReason !== undefined) {
        throw new ScanRunnableInterruptedError(interruptReason);
      }

      await processBatch({
        batch,
        context,
      });
    }
  };

  const runScan = async (requestIDs: string[]): Promise<ScanResult> => {
    try {
      hasRun = true;
      emit("scan:started", {});

      const scheduler = createScheduler(config.concurrentTargets);
      await runTasksWithScheduler({
        scheduler,
        jobs: requestIDs.map((requestID) => {
          return async () => {
            const interruptReason = interruptController.getReason();
            if (interruptReason !== undefined) {
              throw new ScanRunnableInterruptedError(interruptReason);
            }

            await processTarget(requestID);
          };
        }),
      });

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

  return {
    run: async (requestIDs: string[]): Promise<ScanResult> => {
      if (hasRun) {
        return { kind: "Error", error: "Scan is already running" };
      }

      if (config.scanTimeout <= 0) {
        return runScan(requestIDs);
      }

      let finished = false;
      let timedOut = false;
      let timeoutId: ReturnType<typeof setTimeout> | undefined;
      const timeoutPromise = new Promise<"timeout">((resolve) => {
        timeoutId = setTimeout(() => {
          if (!finished && interruptController.getReason() === undefined) {
            timedOut = true;
            interruptController.setReason("Timeout");
          }
          resolve("timeout");
        }, config.scanTimeout * 1000);
      });

      const runPromise = runScan(requestIDs).finally(() => {
        finished = true;
        if (timeoutId !== undefined) {
          clearTimeout(timeoutId);
        }
      });

      const result = await Promise.race([runPromise, timeoutPromise]);
      if (result === "timeout") {
        const finalResult = await runPromise;
        if (finalResult.kind === "Finished" && timedOut) {
          emit("scan:interrupted", { reason: "Timeout" });
          return {
            kind: "Interrupted",
            reason: "Timeout",
            findings: finalResult.findings,
          };
        }

        return finalResult;
      }
      return result;
    },
    estimate: async (requestIDs: string[]): Promise<ScanEstimateResult> => {
      let checksTotal = 0;
      const snapshotDedupeKeys = createDedupeKeysSnapshot(dedupeKeys);

      for (const requestID of requestIDs) {
        const target = await sdk.requests.get(requestID);
        if (target === undefined) {
          return { kind: "Error", error: `Request ${requestID} not found` };
        }
        if (!isTargetInScope(target.request)) {
          continue;
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
      if (interruptController.getReason() !== undefined || !hasRun) {
        return;
      }

      interruptController.setReason(reason);
      await new Promise<void>((resolve) => {
        on("scan:interrupted", () => resolve());
      });
    },
    externalDedupeKeys,
    on: (event, callback) => on(event, callback),
    emit: (event, data) => emit(event, data),
    getExecutionHistory: () => history.getHistory(),
  };
};

export { evaluateCheckApplicability, getCheckBatches } from "./utils";
