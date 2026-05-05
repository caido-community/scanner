import { Result, type ScanRequestPayload, type Session } from "shared";

import { IdSchema, SessionTitleSchema } from "../../schemas";
import { requireSDK } from "../../sdk";
import { ScannerStore } from "../../stores/scanner";
import { validateInput } from "../../utils/validation";

import { startActiveScan } from "./execution";

export const getScanSession = (id: string): Result<Session> => {
  const validation = validateInput(IdSchema, id);
  if (validation.kind === "Error") {
    return validation;
  }

  const session = ScannerStore.get().getSession(validation.value);
  if (!session) {
    return Result.err(`Session ${validation.value} not found`);
  }

  return Result.ok(session);
};

export const getScanSessions = (): Result<Session[]> => {
  const sessions = ScannerStore.get().listSessions();
  return Result.ok(sessions);
};

export const cancelScanSession = async (
  id: string,
): Promise<Result<boolean>> => {
  const validation = validateInput(IdSchema, id);
  if (validation.kind === "Error") {
    return validation;
  }

  const store = ScannerStore.get();
  const result = await store.cancelRunnable(validation.value);
  return Result.ok(result);
};

export const deleteScanSession = (id: string): Result<boolean> => {
  const validation = validateInput(IdSchema, id);
  if (validation.kind === "Error") {
    return validation;
  }

  const result = ScannerStore.get().deleteSession(validation.value);
  return Result.ok(result);
};

export const updateSessionTitle = (
  id: string,
  title: string,
): Result<Session> => {
  const idValidation = validateInput(IdSchema, id);
  if (idValidation.kind === "Error") {
    return idValidation;
  }

  const titleValidation = validateInput(SessionTitleSchema, title);
  if (titleValidation.kind === "Error") {
    return titleValidation;
  }

  const result = ScannerStore.get().updateSessionTitle(
    idValidation.value,
    titleValidation.value,
  );
  if (!result) {
    return Result.err(`Session ${idValidation.value} not found`);
  }

  requireSDK().api.send("session:updated", idValidation.value, result);
  return Result.ok(result);
};

export const rerunScanSession = async (
  id: string,
): Promise<Result<Session>> => {
  const validation = validateInput(IdSchema, id);
  if (validation.kind === "Error") {
    return validation;
  }

  const session = ScannerStore.get().getSession(validation.value);
  if (!session) {
    return Result.err(`Session ${validation.value} not found`);
  }

  const payload: ScanRequestPayload = {
    requestIDs: session.requestIDs,
    scanConfig: session.scanConfig,
    title: `${session.title} (Rerun)`,
  };

  return await startActiveScan(payload);
};

export const getExecutionTrace = (sessionId: string): Result<string> => {
  const validation = validateInput(IdSchema, sessionId);
  if (validation.kind === "Error") {
    return validation;
  }

  const trace = ScannerStore.get().getExecutionTrace(validation.value);
  if (trace === undefined) {
    return Result.err("Execution trace not found");
  }

  return Result.ok(trace);
};
