import { createRegistry } from "engine";
import { Result, type ScanRequestPayload, type Session } from "shared";

import { ScanRequestPayloadSchema } from "../../schemas";
import { requireSDK } from "../../sdk";
import { ChecksStore } from "../../stores/checks";
import { ConfigStore } from "../../stores/config";
import { ScannerStore } from "../../stores/scanner";
import { packExecutionHistory } from "../../utils/debug";
import { validateInput } from "../../utils/validation";

export const startActiveScan = async (
  payload: ScanRequestPayload,
): Promise<Result<Session>> => {
  const validation = validateInput(ScanRequestPayloadSchema, payload);
  if (validation.kind === "Error") {
    return validation;
  }

  const sdk = requireSDK();
  const { requestIDs, scanConfig, title } = validation.value;

  const userConfig = ConfigStore.get().getUserConfig();
  const activeChecks = ChecksStore.get().select({
    overrides: userConfig.active.overrides,
  });

  if (activeChecks.length === 0) {
    return Result.err("No active scans available");
  }

  for (const requestID of requestIDs) {
    const request = await sdk.requests.get(requestID);
    if (!request) {
      return Result.err(`Request ${requestID} not found`);
    }
  }

  const scannerStore = ScannerStore.get();
  const initialSession = scannerStore.createSession(
    title,
    requestIDs,
    scanConfig,
  );
  sdk.api.send("session:created", initialSession.id, initialSession);

  void runSession(initialSession.id, requestIDs, scanConfig, activeChecks);

  return Result.ok(initialSession);
};

const runSession = async (
  id: string,
  requestIDs: string[],
  scanConfig: ScanRequestPayload["scanConfig"],
  activeChecks: ReturnType<ChecksStore["select"]>,
): Promise<void> => {
  const sdk = requireSDK();
  const scannerStore = ScannerStore.get();

  try {
    const registry = createRegistry();
    for (const check of activeChecks) {
      registry.register(check);
    }

    const runnable = registry.create(sdk, scanConfig);
    scannerStore.registerRunnable(id, runnable);

    const emitExecutionPatch = (checkID: string, targetRequestID: string) => {
      const execution = scannerStore.getCheckExecution(
        id,
        checkID,
        targetRequestID,
      );
      if (execution === undefined) {
        return;
      }

      sdk.api.send("session:progress", id, {
        type: "upsertExecution",
        execution,
      });
    };

    const estimate = await runnable.estimate(requestIDs);
    if (estimate.kind === "Error") {
      throw new Error(estimate.error);
    }

    const startedSession = scannerStore.startSession(id, estimate.checksTotal);
    if (!startedSession) {
      throw new Error("Failed to start session");
    }

    sdk.api.send("session:updated", id, startedSession);

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
        emitExecutionPatch(checkID, targetRequestID);

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
      if (
        scannerStore.completeCheck(id, checkID, targetRequestID) === undefined
      )
        return;
      emitExecutionPatch(checkID, targetRequestID);
    });

    runnable.on(
      "scan:request-pending",
      ({ pendingRequestID, targetRequestID, checkID }) => {
        if (
          scannerStore.addRequestSent(
            id,
            checkID,
            targetRequestID,
            pendingRequestID,
          ) === undefined
        )
          return;
        emitExecutionPatch(checkID, targetRequestID);
      },
    );

    runnable.on(
      "scan:request-completed",
      ({ pendingRequestID, requestID, checkID, targetRequestID }) => {
        if (
          scannerStore.completeRequest(id, pendingRequestID, requestID) ===
          undefined
        )
          return;
        emitExecutionPatch(checkID, targetRequestID);
      },
    );

    runnable.on(
      "scan:request-failed",
      ({ error, pendingRequestID, checkID, targetRequestID }) => {
        if (scannerStore.failRequest(id, pendingRequestID, error) === undefined)
          return;
        emitExecutionPatch(checkID, targetRequestID);
      },
    );

    runnable.on("scan:check-started", ({ checkID, targetRequestID }) => {
      if (scannerStore.startCheck(id, checkID, targetRequestID) === undefined)
        return;
      emitExecutionPatch(checkID, targetRequestID);
    });

    runnable.on(
      "scan:check-failed",
      ({ checkID, errorMessage, targetRequestID }) => {
        if (
          scannerStore.failCheck(
            id,
            checkID,
            targetRequestID,
            errorMessage || "Unknown error",
          ) === undefined
        )
          return;
        emitExecutionPatch(checkID, targetRequestID);
      },
    );

    const result = await runnable.run(requestIDs);
    const trace = packExecutionHistory(runnable.getExecutionHistory());

    switch (result.kind) {
      case "Finished": {
        const finishedSession = scannerStore.finishSession(id, trace);
        if (finishedSession) {
          sdk.api.send("session:updated", id, finishedSession);
        }
        break;
      }
      case "Interrupted": {
        const interruptedSession = scannerStore.interruptSession(
          id,
          result.reason,
          trace,
        );
        if (interruptedSession) {
          sdk.api.send("session:updated", id, interruptedSession);
        }
        break;
      }
      case "Error": {
        const errorSession = scannerStore.errorSession(id, result.error, trace);
        if (errorSession) {
          sdk.api.send("session:updated", id, errorSession);
        }
        break;
      }
    }
  } catch (err) {
    const errorSession = scannerStore.errorSession(
      id,
      err instanceof Error ? err.message : "Unknown error",
      undefined,
    );
    if (errorSession) {
      sdk.api.send("session:updated", id, errorSession);
    }
  } finally {
    scannerStore.unregisterRunnable(id);
  }
};
