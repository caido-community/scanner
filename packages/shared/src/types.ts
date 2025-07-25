import {
  type CheckType,
  type Finding,
  type InterruptReason,
  type ScanAggressivity,
  type ScanConfig,
  type Severity,
} from "engine";

/**
 * UserConfig is the configuration for the user.
 *
 * Overrides are used to enable or disable checks.
 * By default:
 * - for active scans, all checks are enabled including passive
 * - for passive scans, all passive checks are enabled
 * Overrides are used to force enable or disable checks.
 */
export type UserConfig = {
  passive: {
    enabled: boolean;
    aggressivity: ScanAggressivity;
    inScopeOnly: boolean;
    concurrentChecks: number;
    concurrentRequests: number;
    overrides: Override[];
    severities: Severity[];
  };
  active: {
    overrides: Override[];
  };
  presets: Preset[];
};

export type Preset = {
  name: string;
  active: Override[];
  passive: Override[];
};

export type Override = {
  enabled: boolean;
  checkID: string;
};

export type SelectOptions = {
  type?: CheckType;
  include?: string[];
  exclude?: string[];
  returnMetadata?: boolean;
  overrides?: Override[];
};

export type GetChecksOptions = Pick<
  SelectOptions,
  "type" | "include" | "exclude"
>;

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

export type Session =
  | { kind: "Pending"; id: string; createdAt: number; title: string }
  | {
      kind: "Running";
      id: string;
      title: string;
      createdAt: number;
      startedAt: number;
      progress: SessionProgress;
    }
  | {
      kind: "Done";
      id: string;
      title: string;
      createdAt: number;
      startedAt: number;
      finishedAt: number;
      progress: SessionProgress;
    }
  | {
      kind: "Interrupted";
      id: string;
      title: string;
      createdAt: number;
      startedAt: number;
      progress: SessionProgress;
      reason: InterruptReason;
    }
  | {
      kind: "Error";
      id: string;
      title: string;
      createdAt: number;
      error: string;
    };

export type ScanRequestPayload = {
  requestIDs: string[];
  scanConfig: ScanConfig;
  title: string;
};

export type BasicRequest = {
  id: string;
  host: string;
  port: number;
  path: string;
  query: string;
  method: string;
};

export type QueueTask = {
  id: string;
  requestID: string;
  status: "pending" | "running";
};

export type Result<T> =
  | { kind: "Error"; error: string }
  | { kind: "Success"; value: T };

export function ok<T>(value: T): Result<T> {
  return { kind: "Success", value };
}

export function error<T>(error: string): Result<T> {
  return { kind: "Error", error };
}

export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};
