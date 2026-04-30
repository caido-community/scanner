import type { Finding } from "./finding";
import type { InterruptReason, ScanConfig } from "./scan";

export type SentRequest =
  | {
      status: "pending";
      pendingRequestID: string;
      sentAt: number;
    }
  | {
      status: "completed";
      pendingRequestID: string;
      requestID: string;
      sentAt: number;
      completedAt: number;
    }
  | {
      status: "failed";
      pendingRequestID: string;
      error: string;
      sentAt: number;
      completedAt: number;
    };

export type CheckExecution =
  | {
      kind: "Running";
      id: string;
      checkID: string;
      targetRequestID: string;
      startedAt: number;
      requestsSent: SentRequest[];
      findings: Finding[];
    }
  | {
      kind: "Completed";
      id: string;
      checkID: string;
      targetRequestID: string;
      startedAt: number;
      completedAt: number;
      requestsSent: SentRequest[];
      findings: Finding[];
    }
  | {
      kind: "Failed";
      id: string;
      checkID: string;
      targetRequestID: string;
      startedAt: number;
      failedAt: number;
      error: string;
      requestsSent: SentRequest[];
      findings: Finding[];
    };

export type SessionProgress = {
  checksTotal: number;
  checksHistory: CheckExecution[];
};

export type SessionProgressPatch = {
  type: "upsertExecution";
  execution: CheckExecution;
};

export type Session =
  | {
      kind: "Pending";
      id: string;
      createdAt: number;
      title: string;
      requestIDs: string[];
      scanConfig: ScanConfig;
    }
  | {
      kind: "Running";
      id: string;
      title: string;
      createdAt: number;
      startedAt: number;
      progress: SessionProgress;
      requestIDs: string[];
      scanConfig: ScanConfig;
    }
  | {
      kind: "Done";
      id: string;
      title: string;
      createdAt: number;
      startedAt: number;
      finishedAt: number;
      progress: SessionProgress;
      hasExecutionTrace: boolean;
      requestIDs: string[];
      scanConfig: ScanConfig;
    }
  | {
      kind: "Interrupted";
      id: string;
      title: string;
      createdAt: number;
      startedAt: number;
      progress: SessionProgress;
      reason: InterruptReason;
      hasExecutionTrace: boolean;
      requestIDs: string[];
      scanConfig: ScanConfig;
    }
  | {
      kind: "Error";
      id: string;
      title: string;
      createdAt: number;
      error: string;
      hasExecutionTrace: boolean;
      requestIDs: string[];
      scanConfig: ScanConfig;
    };

export type ScanRequestPayload = {
  requestIDs: string[];
  scanConfig: ScanConfig;
  title: string;
};
