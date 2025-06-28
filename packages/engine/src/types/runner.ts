import type { SDK } from "caido:plugin";
import type { Request, Response } from "caido:utils";

import type { Finding } from "./finding";
import type { ScanRuntime } from "./runtime";

export type ScanState =
  | "Idle"
  | "Running"
  | "Finished"
  | "Interrupted"
  | "Error";

export type ScanCallbacks = {
  onFinding?: (finding: Finding) => void;
  onCheckFinished?: (checkID: string) => void;
  onRequest?: (requestID: string, responseID: string) => void;
};

export type InterruptReason = "Cancelled" | "Timeout";
export type ScanResult =
  | {
      kind: "Finished";
      findings: Finding[];
    }
  | {
      kind: "Interrupted";
      reason: InterruptReason;
    }
  | {
      kind: "Error";
      error: string;
    };

export const ScanStrength = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
} as const;

export type ScanStrength = (typeof ScanStrength)[keyof typeof ScanStrength];

export type ScanConfig = {
  strength: ScanStrength;
  callbacks?: ScanCallbacks;
};

export type CheckTarget = {
  request: Request;
  response?: Response;
};

export type CheckContext = CheckTarget & {
  sdk: SDK;
  runtime: ScanRuntime;
  config: ScanConfig;
};
