import type { Severity } from "./severity";

export type CheckType = "passive" | "active";

export const ScanAggressivity = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
} as const;

export type ScanAggressivity =
  (typeof ScanAggressivity)[keyof typeof ScanAggressivity];

export type InterruptReason =
  | "Cancelled"
  | "Timeout"
  | "ProjectChanged"
  | "RuntimeStopped";

export type ScanConfig = {
  aggressivity: ScanAggressivity;
  scopeIDs: string[];
  concurrentChecks: number;
  concurrentRequests: number;
  concurrentTargets: number;
  requestsDelayMs: number;
  scanTimeout: number;
  checkTimeout: number;
  requestTimeout?: number;
  severities: Severity[];
};
