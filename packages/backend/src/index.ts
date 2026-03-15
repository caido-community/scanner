import type { DefineAPI } from "caido:plugin";
import {
  createPrefixedRandomId,
  createRegistry,
  createScheduler,
  Result,
} from "engine";
import type { BasicRequest, Result as ResultType } from "shared";

import { checks } from "./checks";
import { IdSchema } from "./schemas";
import { getChecks } from "./services/checks";
import { getUserConfig, updateUserConfig } from "./services/config";
import { clearQueueTasks, getQueueTask, getQueueTasks } from "./services/queue";
import {
  cancelScanSession,
  deleteScanSession,
  getScanSession,
  getScanSessions,
  rerunScanSession,
  startActiveScan,
  updateSessionTitle,
} from "./services/scanner";
import { ChecksStore } from "./stores/checks";
import { ConfigStore } from "./stores/config";
import { QueueStore } from "./stores/queue";
import { ScannerStore } from "./stores/scanner";
import { type BackendSDK } from "./types";
import { packExecutionHistory } from "./utils/debug";
import { validateInput } from "./utils/validation";

export { type BackendEvents } from "./types";

export type API = DefineAPI<{
  // Checks
  getChecks: typeof getChecks;

  // Config
  getUserConfig: typeof getUserConfig;
  updateUserConfig: typeof updateUserConfig;

  // Queue
  getQueueTasks: typeof getQueueTasks;
  getQueueTask: typeof getQueueTask;
  clearQueueTasks: typeof clearQueueTasks;

  // Scanner
  startActiveScan: typeof startActiveScan;
  getScanSession: typeof getScanSession;
  getScanSessions: typeof getScanSessions;
  cancelScanSession: typeof cancelScanSession;
  deleteScanSession: typeof deleteScanSession;
  getRequestResponse: typeof getRequestResponse;
  updateSessionTitle: typeof updateSessionTitle;
  getExecutionTrace: typeof getExecutionTrace;
  rerunScanSession: typeof rerunScanSession;
}>;

export async function init(sdk: BackendSDK) {
  sdk.api.register("getChecks", getChecks);
  sdk.api.register("getUserConfig", getUserConfig);
  sdk.api.register("updateUserConfig", updateUserConfig);
  sdk.api.register("getQueueTasks", getQueueTasks);
  sdk.api.register("getQueueTask", getQueueTask);
  sdk.api.register("clearQueueTasks", clearQueueTasks);
  sdk.api.register("startActiveScan", startActiveScan);
  sdk.api.register("getScanSession", getScanSession);
  sdk.api.register("getScanSessions", getScanSessions);
  sdk.api.register("cancelScanSession", cancelScanSession);
  sdk.api.register("deleteScanSession", deleteScanSession);
  sdk.api.register("getRequestResponse", getRequestResponse);
  sdk.api.register("updateSessionTitle", updateSessionTitle);
  sdk.api.register("getExecutionTrace", getExecutionTrace);
  sdk.api.register("rerunScanSession", rerunScanSession);

  const checksStore = ChecksStore.get();
  checksStore.register(...checks);

  const configStore = ConfigStore.get();
  const scannerStore = ScannerStore.get();
  const queueStore = QueueStore.get();

  await configStore.initialize(sdk);
  await scannerStore.initialize(sdk);
  const project = await sdk.projects.getCurrent();
  queueStore.switchProject(project?.getId());

  const config = configStore.getUserConfig();
  const passiveTaskQueue = createScheduler(config.passive.concurrentTargets);
  queueStore.setPassiveTaskQueue(passiveTaskQueue);
  let passiveDedupeKeys = new Map<string, Set<string>>();
  let passiveQueueSnapshotTimeout: Timeout | undefined;
  const emitPassiveQueueSnapshot = () => {
    if (passiveQueueSnapshotTimeout !== undefined) {
      return;
    }

    passiveQueueSnapshotTimeout = setTimeout(() => {
      sdk.api.send("passive:queue-updated", queueStore.getTasks());
      passiveQueueSnapshotTimeout = undefined;
    }, 150);
  };
  sdk.events.onInterceptResponse((sdk, request) => {
    const config = configStore.getUserConfig();
    if (!config.passive.enabled) return;

    passiveTaskQueue.setConcurrency(config.passive.concurrentTargets);

    if (config.passive.scopeIDs.length > 0) {
      const inScope = sdk.requests.inScope(request, config.passive.scopeIDs);
      if (!inScope) return;
    }

    const passiveChecks = checksStore.select({
      type: "passive",
      overrides: config.passive.overrides,
    });

    if (passiveChecks.length === 0) {
      return;
    }

    const passiveTaskID = createPrefixedRandomId("pscan-");
    queueStore.addTask(passiveTaskID, toBasicRequest(request));
    emitPassiveQueueSnapshot();

    void passiveTaskQueue
      .schedule(async () => {
        const registry = createRegistry();
        for (const check of passiveChecks) {
          registry.register(check);
        }

        const requestTimeout = config.requestTimeout ?? 2 * 60;
        const runnable = registry.create(sdk, {
          aggressivity: config.passive.aggressivity,
          scopeIDs: config.passive.scopeIDs,
          concurrentChecks: 2,
          concurrentRequests: config.passive.concurrentRequests,
          concurrentTargets: 1,
          severities: config.passive.severities,
          scanTimeout: 5 * 60,
          checkTimeout: 2 * 60,
          requestTimeout,
          requestsDelayMs: 0,
        });

        runnable.externalDedupeKeys(passiveDedupeKeys);

        try {
          queueStore.addActiveRunnable(passiveTaskID, runnable);
          queueStore.updateTaskStatus(passiveTaskID, "running");
          emitPassiveQueueSnapshot();

          runnable.on("scan:check-started", ({ checkID }) => {
            queueStore.addExecutedCheck(passiveTaskID, checkID);
            emitPassiveQueueSnapshot();
          });

          runnable.on("scan:finding", async ({ finding, checkID }) => {
            const request = await sdk.requests.get(
              finding.correlation.requestID,
            );
            if (!request) return;
            if (!config.passive.severities.includes(finding.severity)) return;

            const wrappedDescription = `This finding has been assessed as \`${finding.severity.toUpperCase()}\` severity and was discovered by the \`${checkID}\` check.\n\n${
              finding.description
            }`;

            sdk.findings.create({
              reporter: "Scanner: Passive",
              request: request.request,
              title: finding.name,
              description: wrappedDescription,
            });
          });

          const result = await runnable.run([request.getId()]);
          switch (result.kind) {
            case "Finished":
              queueStore.updateTaskStatus(passiveTaskID, "completed");
              break;
            case "Interrupted":
              queueStore.updateTaskStatus(
                passiveTaskID,
                "cancelled",
                result.reason,
              );
              break;
            case "Error":
              queueStore.updateTaskStatus(
                passiveTaskID,
                "failed",
                result.error,
              );
              break;
          }
        } catch (error) {
          queueStore.updateTaskStatus(
            passiveTaskID,
            "failed",
            error instanceof Error ? error.message : "Unknown error",
          );
        } finally {
          queueStore.removeActiveRunnable(passiveTaskID);
          emitPassiveQueueSnapshot();
        }
      })
      .promise.catch((error: unknown) => {
        queueStore.updateTaskStatus(
          passiveTaskID,
          "cancelled",
          error instanceof Error ? error.message : "Cancelled",
        );
        emitPassiveQueueSnapshot();
      });
  });

  sdk.events.onProjectChange(async (sdk, project) => {
    const projectId = project?.getId();
    sdk.api.send("project:changed", projectId, "start");
    queueStore.clearTasks();
    emitPassiveQueueSnapshot();
    passiveDedupeKeys = new Map<string, Set<string>>();

    const runningSessionIds = scannerStore.listRunningSessionIds();
    for (const sessionId of runningSessionIds) {
      const runnable = scannerStore.getRunnable(sessionId);
      const trace =
        runnable === undefined
          ? ""
          : packExecutionHistory(runnable.getExecutionHistory());
      scannerStore.interruptSession(sessionId, "ProjectChanged", trace);
      void runnable?.cancel("ProjectChanged");
    }

    await configStore.switchProject(projectId);
    await scannerStore.switchProject(projectId);
    queueStore.switchProject(projectId);
    emitPassiveQueueSnapshot();

    sdk.api.send("project:changed", projectId, "ready");
  });
}

export const getRequestResponse = async (
  sdk: BackendSDK,
  requestId: string,
): Promise<
  ResultType<{
    request: { id: string; raw: string };
    response: { id: string; raw: string };
  }>
> => {
  const validation = validateInput(IdSchema, requestId);
  if (validation.kind === "Error") {
    return validation;
  }

  const result = await sdk.requests.get(validation.value);

  if (!result) {
    return Result.err("Request not found");
  }

  const { request, response } = result;

  if (!response) {
    return Result.err("Response not found");
  }

  return Result.ok({
    request: {
      id: request.getId(),
      raw: Uint8ArrayToString(request.toSpecRaw().getRaw()),
    },
    response: {
      id: response.getId(),
      raw: response.getRaw().toText(),
    },
  });
};

const toBasicRequest = (request: {
  getId: () => string;
  getHost: () => string;
  getPort: () => number;
  getPath: () => string;
  getQuery: () => string;
  getMethod: () => string;
}): BasicRequest => ({
  id: request.getId(),
  host: request.getHost(),
  port: request.getPort(),
  path: request.getPath(),
  query: request.getQuery(),
  method: request.getMethod().toUpperCase(),
});

export const getExecutionTrace = (
  sdk: BackendSDK,
  sessionId: string,
): ResultType<string> => {
  const validation = validateInput(IdSchema, sessionId);
  if (validation.kind === "Error") {
    return validation;
  }

  const scannerStore = ScannerStore.get();
  const trace = scannerStore.getExecutionTrace(validation.value);

  if (trace === undefined) {
    return Result.err("Execution trace not found");
  }

  return Result.ok(trace);
};

const Uint8ArrayToString = (data: Uint8Array) => {
  let output = "";
  const chunkSize = 256;
  for (let i = 0; i < data.length; i += chunkSize) {
    output += String.fromCharCode(...data.subarray(i, i + chunkSize));
  }

  return output;
};
