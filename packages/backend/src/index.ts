import {
  createPrefixedRandomId,
  createRegistry,
  createScheduler,
} from "engine";

import * as api from "./api";
import { checks } from "./checks";
import { setSDK } from "./sdk";
import { ChecksStore } from "./stores/checks";
import { ConfigStore } from "./stores/config";
import { QueueStore } from "./stores/queue";
import { ScannerStore } from "./stores/scanner";
import { type BackendSDK } from "./types";
import { packExecutionHistory } from "./utils/debug";
import { toBasicRequest } from "./utils/request";

export async function init(sdk: BackendSDK) {
  setSDK(sdk);

  sdk.api.register("getChecks", api.apiGetChecks);
  sdk.api.register("getUserConfig", api.apiGetUserConfig);
  sdk.api.register("updateUserConfig", api.apiUpdateUserConfig);
  sdk.api.register("getQueueTasks", api.apiGetQueueTasks);
  sdk.api.register("getQueueTask", api.apiGetQueueTask);
  sdk.api.register("clearQueueTasks", api.apiClearQueueTasks);
  sdk.api.register("startActiveScan", api.apiStartActiveScan);
  sdk.api.register("getScanSession", api.apiGetScanSession);
  sdk.api.register("getScanSessions", api.apiGetScanSessions);
  sdk.api.register("cancelScanSession", api.apiCancelScanSession);
  sdk.api.register("deleteScanSession", api.apiDeleteScanSession);
  sdk.api.register("updateSessionTitle", api.apiUpdateSessionTitle);
  sdk.api.register("rerunScanSession", api.apiRerunScanSession);
  sdk.api.register("getRequestResponse", api.apiGetRequestResponse);
  sdk.api.register("getExecutionTrace", api.apiGetExecutionTrace);

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
