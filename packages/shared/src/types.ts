import type {
  CheckType,
  Finding,
  InterruptReason,
  ScanAggressivity,
  ScanConfig,
  Severity,
} from "engine";

export { Result } from "engine";

/**
 * UserConfig is the configuration for the user.
 *
 * Overrides are used to enable or disable checks.
 * By default:
 * - for active scans, all checks are enabled including passive
 * - for passive scans, all passive checks are enabled
 * Overrides are used to force enable or disable checks.
 */
export type PassiveConfig = {
  enabled: boolean;
  aggressivity: ScanAggressivity;
  inScopeOnly: boolean;
  concurrentChecks: number;
  concurrentRequests: number;
  overrides: Override[];
  severities: Severity[];
};

export type ActiveConfig = {
  overrides: Override[];
};

export type Override = {
  enabled: boolean;
  checkID: string;
};

export type Preset = {
  name: string;
  active: Override[];
  passive: Override[];
};

export type UserConfig = {
  passive: PassiveConfig;
  active: ActiveConfig;
  presets: Preset[];
  defaultPresetName?: string;
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

export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};
