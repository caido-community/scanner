import { createRegistry, Result } from "engine";
import type { Result as ResultType, ScanRequestPayload, Session } from "shared";

import { ScanRequestPayloadSchema } from "../../schemas";
import { ChecksStore } from "../../stores/checks";
import { ConfigStore } from "../../stores/config";
import { ScannerStore } from "../../stores/scanner";
import { type BackendSDK } from "../../types";
import { packExecutionHistory } from "../../utils/debug";
import { validateInput } from "../../utils/validation";

export const startActiveScan = (
  sdk: BackendSDK,
  payload: ScanRequestPayload,
): ResultType<Session> => {
  const validation = validateInput(ScanRequestPayloadSchema, payload);
  if (validation.kind === "Error") {
    return validation;
  }

  const { requestIDs, scanConfig, title } = validation.value;

  const configStore = ConfigStore.get();
  const userConfig = configStore.getUserConfig();

  const checksStore = ChecksStore.get();
  const activeChecks = checksStore.select({
    overrides: userConfig.active.overrides,
  });

  if (activeChecks.length === 0) {
    return Result.err("No active scans available");
  }

  const scannerStore = ScannerStore.get();
  const initialSession = scannerStore.createSession(
    title,
    requestIDs,
    scanConfig,
  );

  (async () => {
    const { id } = initialSession;

    try {
      const registry = createRegistry();
      for (const check of activeChecks) {
        registry.register(check);
      }

      const runnable = registry.create(sdk, scanConfig);
      scannerStore.registerRunnable(id, runnable);

      const estimate = await runnable.estimate(requestIDs);
      if (estimate.kind === "Error") {
        throw new Error(estimate.error);
      }

      const startedSession = scannerStore.startSession(
        id,
        estimate.checksTotal,
      );
      if (!startedSession) {
        throw new Error("Failed to start session");
      }

      sdk.api.send("session:created", id, startedSession, {
        checksTotal: estimate.checksTotal,
      });

      runnable.on(
        "scan:finding",
        async ({ finding, targetRequestID, checkID }) => {
          if (!scanConfig.severities.includes(finding.severity)) {
            return;
          }

          const findingAddedSession = scannerStore.addFinding(
            id,
            checkID,
            targetRequestID,
            finding,
          );
          if (!findingAddedSession) return;

          sdk.api.send("session:updated", id, findingAddedSession);

          const result = await sdk.requests.get(finding.correlation.requestID);
          if (!result) return;

          const wrappedDescription = `This finding has been assessed as \`${finding.severity.toUpperCase()}\` severity and was discovered by the \`${checkID}\` check.\n\n${finding.description}`;

          sdk.findings.create({
            request: result.request,
            reporter: "Scanner: Active",
            title: finding.name,
            description: wrappedDescription,
          });
        },
      );

      runnable.on("scan:check-finished", ({ checkID, targetRequestID }) => {
        const checkFinishedSession = scannerStore.completeCheck(
          id,
          checkID,
          targetRequestID,
        );
        if (!checkFinishedSession || checkFinishedSession.kind !== "Running")
          return;

        sdk.api.send("session:progress", id, checkFinishedSession.progress);
      });

      runnable.on(
        "scan:request-pending",
        ({ pendingRequestID, targetRequestID, checkID }) => {
          const requestPendingSession = scannerStore.addRequestSent(
            id,
            checkID,
            targetRequestID,
            pendingRequestID,
          );

          if (
            !requestPendingSession ||
            requestPendingSession.kind !== "Running"
          )
            return;

          sdk.api.send("session:progress", id, requestPendingSession.progress);
        },
      );

      runnable.on(
        "scan:request-completed",
        ({ pendingRequestID, requestID }) => {
          const requestCompletedSession = scannerStore.completeRequest(
            id,
            pendingRequestID,
            requestID,
          );
          if (
            !requestCompletedSession ||
            requestCompletedSession.kind !== "Running"
          )
            return;

          sdk.api.send(
            "session:progress",
            id,
            requestCompletedSession.progress,
          );
        },
      );

      runnable.on("scan:request-failed", ({ error, pendingRequestID }) => {
        const requestFailedSession = scannerStore.failRequest(
          id,
          pendingRequestID,
          error,
        );
        if (!requestFailedSession || requestFailedSession.kind !== "Running")
          return;

        sdk.api.send("session:progress", id, requestFailedSession.progress);
      });

      runnable.on("scan:check-started", ({ checkID, targetRequestID }) => {
        const checkRunningSession = scannerStore.startCheck(
          id,
          checkID,
          targetRequestID,
        );
        if (!checkRunningSession || checkRunningSession.kind !== "Running")
          return;

        sdk.api.send("session:progress", id, checkRunningSession.progress);
      });

      runnable.on(
        "scan:check-failed",
        ({ checkID, errorMessage, targetRequestID }) => {
          const checkFailedSession = scannerStore.failCheck(
            id,
            checkID,
            targetRequestID,
            errorMessage || "Unknown error",
          );
          if (!checkFailedSession || checkFailedSession.kind !== "Running")
            return;

          sdk.api.send("session:progress", id, checkFailedSession.progress);
        },
      );

      const result = await runnable.run(requestIDs);
      const executionHistory = runnable.getExecutionHistory();
      const trace = packExecutionHistory(executionHistory);

      switch (result.kind) {
        case "Finished": {
          const finishedSession = scannerStore.finishSession(id, trace);
          if (!finishedSession) break;

          sdk.api.send("session:updated", id, finishedSession);
          break;
        }
        case "Interrupted": {
          const interruptedSession = scannerStore.interruptSession(
            id,
            result.reason,
            trace,
          );
          if (!interruptedSession) break;

          sdk.api.send("session:updated", id, interruptedSession);
          break;
        }
        case "Error": {
          const errorSession = scannerStore.errorSession(
            id,
            result.error,
            trace,
          );
          if (!errorSession) break;

          sdk.api.send("session:updated", id, errorSession);
          break;
        }
      }
    } catch (err) {
      const errorSession = scannerStore.errorSession(
        id,
        err instanceof Error ? err.message : "Unknown error",
        undefined,
      );
      if (!errorSession) return;
      sdk.api.send("session:updated", id, errorSession);
    } finally {
      scannerStore.unregisterRunnable(id);
    }
  })();

  return Result.ok(initialSession);
};
