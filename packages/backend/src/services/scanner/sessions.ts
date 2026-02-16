import { Result } from "engine";
import type { Result as ResultType, ScanRequestPayload, Session } from "shared";

import { IdSchema, SessionTitleSchema } from "../../schemas";
import { ScannerStore } from "../../stores/scanner";
import { type BackendSDK } from "../../types";
import { validateInput } from "../../utils/validation";

import { startActiveScan } from "./execution";

export const getScanSession = (
  _: BackendSDK,
  id: string,
): ResultType<Session> => {
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

export const getScanSessions = (_: BackendSDK): ResultType<Session[]> => {
  const sessions = ScannerStore.get().listSessions();
  return Result.ok(sessions);
};

export const cancelScanSession = async (
  _: BackendSDK,
  id: string,
): Promise<ResultType<boolean>> => {
  const validation = validateInput(IdSchema, id);
  if (validation.kind === "Error") {
    return validation;
  }

  const store = ScannerStore.get();
  const result = await store.cancelRunnable(validation.value);
  return Result.ok(result);
};

export const deleteScanSession = (
  _: BackendSDK,
  id: string,
): ResultType<boolean> => {
  const validation = validateInput(IdSchema, id);
  if (validation.kind === "Error") {
    return validation;
  }

  const result = ScannerStore.get().deleteSession(validation.value);
  return Result.ok(result);
};

export const updateSessionTitle = (
  sdk: BackendSDK,
  id: string,
  title: string,
): ResultType<Session> => {
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

  sdk.api.send("session:updated", idValidation.value, result);
  return Result.ok(result);
};

export const rerunScanSession = (
  sdk: BackendSDK,
  id: string,
): ResultType<Session> => {
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

  return startActiveScan(sdk, payload);
};
