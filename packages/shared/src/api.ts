import type { CheckMetadata } from "./check";
import type { GetChecksOptions, UserConfig } from "./config";
import type { QueueTask } from "./queue";
import type { BasicRequest } from "./request";
import type { Result } from "./result";
import type { ScanRequestPayload, Session } from "./session";

export type API = {
  getChecks: (options?: GetChecksOptions) => Result<CheckMetadata[]>;

  getUserConfig: () => Result<UserConfig>;
  updateUserConfig: (config: Partial<UserConfig>) => Result<void>;

  getQueueTasks: () => Result<QueueTask[]>;
  getQueueTask: (id: string) => Result<QueueTask | undefined>;
  clearQueueTasks: () => Result<void>;

  startActiveScan: (payload: ScanRequestPayload) => Promise<Result<Session>>;
  getScanSession: (id: string) => Result<Session>;
  getScanSessions: () => Result<Session[]>;
  cancelScanSession: (id: string) => Promise<Result<boolean>>;
  deleteScanSession: (id: string) => Result<boolean>;
  updateSessionTitle: (id: string, title: string) => Result<Session>;
  rerunScanSession: (id: string) => Promise<Result<Session>>;
  getRequestResponse: (requestId: string) => Promise<
    Result<{
      request: BasicRequest & { raw: string };
      response: { id: string; raw: string };
    }>
  >;
  getExecutionTrace: (sessionId: string) => Result<string>;
};
