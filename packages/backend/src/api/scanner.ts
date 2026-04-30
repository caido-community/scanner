import type { SDK } from "caido:plugin";
import type { BasicRequest, Result, ScanRequestPayload, Session } from "shared";

import {
  cancelScanSession,
  deleteScanSession,
  getExecutionTrace,
  getRequestResponse,
  getScanSession,
  getScanSessions,
  rerunScanSession,
  startActiveScan,
  updateSessionTitle,
} from "../services/scanner";

export const apiStartActiveScan = (
  _sdk: SDK,
  payload: ScanRequestPayload,
): Promise<Result<Session>> => startActiveScan(payload);

export const apiGetScanSession = (_sdk: SDK, id: string): Result<Session> =>
  getScanSession(id);

export const apiGetScanSessions = (_sdk: SDK): Result<Session[]> =>
  getScanSessions();

export const apiCancelScanSession = (
  _sdk: SDK,
  id: string,
): Promise<Result<boolean>> => cancelScanSession(id);

export const apiDeleteScanSession = (_sdk: SDK, id: string): Result<boolean> =>
  deleteScanSession(id);

export const apiUpdateSessionTitle = (
  _sdk: SDK,
  id: string,
  title: string,
): Result<Session> => updateSessionTitle(id, title);

export const apiRerunScanSession = (
  _sdk: SDK,
  id: string,
): Promise<Result<Session>> => rerunScanSession(id);

export const apiGetRequestResponse = (
  _sdk: SDK,
  requestId: string,
): Promise<
  Result<{
    request: BasicRequest & { raw: string };
    response: { id: string; raw: string };
  }>
> => getRequestResponse(requestId);

export const apiGetExecutionTrace = (
  _sdk: SDK,
  sessionId: string,
): Result<string> => getExecutionTrace(sessionId);
