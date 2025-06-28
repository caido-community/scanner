import {
  type CheckType,
  type Finding,
  type InterruptReason,
  type ScanStrength,
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
    strength: ScanStrength;
    overrides: Record<string, boolean>;
  };
  active: {
    overrides: Record<string, boolean>;
  };
};

export type SelectOptions = {
  type?: CheckType;
  include?: string[];
  exclude?: string[];
  returnMetadata?: boolean;
  overrides?: Record<string, boolean>;
};

export type GetChecksOptions = Pick<
  SelectOptions,
  "type" | "include" | "exclude"
>;

export type SessionProgress = {
  checksCompleted: number;
  requestsSent: number;
};

export type SessionState =
  | { kind: "Pending"; id: string; createdAt: number }
  | {
      kind: "Running";
      id: string;
      createdAt: number;
      startedAt: number;
      findings: Finding[];
      progress: SessionProgress;
    }
  | {
      kind: "Done";
      id: string;
      createdAt: number;
      startedAt: number;
      finishedAt: number;
      findings: Finding[];
      progress: SessionProgress;
    }
  | {
      kind: "Interrupted";
      id: string;
      createdAt: number;
      startedAt: number;
      reason: InterruptReason;
      findings: Finding[];
    }
  | { kind: "Error"; id: string; createdAt: number; error: string };

export type Result<T> =
  | { kind: "Error"; error: string }
  | { kind: "Success"; value: T };

export function ok<T>(value: T): Result<T> {
  return { kind: "Success", value };
}

export function error<T>(error: string): Result<T> {
  return { kind: "Error", error };
}
