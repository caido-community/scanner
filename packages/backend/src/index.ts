import type { DefineAPI } from "caido:plugin";
import { createRegistry, Result } from "engine";
import type { Result as ResultType } from "shared";

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
import { TaskQueue } from "./utils/task-queue";
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

  const config = configStore.getUserConfig();
  const passiveTaskQueue = new TaskQueue(config.passive.concurrentChecks);
  queueStore.setPassiveTaskQueue(passiveTaskQueue);

  const passiveDedupeKeys = new Map<string, Set<string>>();
  sdk.events.onInterceptResponse((sdk, request) => {
    const config = configStore.getUserConfig();
    if (!config.passive.enabled) return;

    passiveTaskQueue.setConcurrency(config.passive.concurrentChecks);

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

    const passiveTaskID =
      "pscan-" + Math.random().toString(36).substring(2, 15);
    queueStore.addTask(passiveTaskID, request.getId());
    sdk.api.send("passive:queue-new", passiveTaskID, request.getId());

    passiveTaskQueue.add(async () => {
      const registry = createRegistry();
      for (const check of passiveChecks) {
        registry.register(check);
      }

      const requestTimeout = config.requestTimeout ?? 2 * 60;
      const runnable = registry.create(sdk, {
        aggressivity: config.passive.aggressivity,
        scopeIDs: config.passive.scopeIDs,
        concurrentChecks: config.passive.concurrentChecks,
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
        sdk.api.send("passive:queue-started", passiveTaskID);

        runnable.on("scan:finding", async ({ finding, checkID }) => {
          const request = await sdk.requests.get(finding.correlation.requestID);
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

        // TODO: handle error, show UI warnings if result kind is not finished
        await runnable.run([request.getId()]);
      } catch (error) {
        // TODO: handle error, show UI warnings
        sdk.console.log("error=", error);
      } finally {
        queueStore.removeActiveRunnable(passiveTaskID);
        queueStore.removeTask(passiveTaskID);
        sdk.api.send("passive:queue-finished", passiveTaskID);
      }
    });
  });

  sdk.events.onProjectChange(async (sdk, project) => {
    const projectId = project?.getId();

    await configStore.switchProject(projectId);
    await scannerStore.switchProject(projectId);

    sdk.api.send("project:changed", projectId);
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
