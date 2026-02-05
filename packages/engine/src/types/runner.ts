import { type SDK } from "caido:plugin";
import { type Request, type Response } from "caido:utils";

import { type ScanRunnableErrorCode } from "../core/errors";
import { type ParsedHtml } from "../utils/html/types";

import { type Check, type CheckOutput } from "./check";
import { type Finding, type Severity } from "./finding";
import { type JSONSerializable } from "./utils";

export const ScanAggressivity = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
} as const;

export type ScanAggressivity =
  (typeof ScanAggressivity)[keyof typeof ScanAggressivity];

export type ScanRegistry = {
  register: (check: Check) => void;
  create: (sdk: SDK, config: ScanConfig) => ScanRunnable;
};

export type ScanRunnable = {
  run: (requestIDs: string[]) => Promise<ScanResult>;
  estimate: (requestIDs: string[]) => Promise<ScanEstimateResult>;
  cancel: (reason: InterruptReason) => Promise<void>;
  externalDedupeKeys: (dedupeKeys: Map<string, Set<string>>) => void;
  getExecutionHistory: () => ExecutionHistory;
  on: <T extends keyof ScanEvents>(
    event: T,
    callback: (data: ScanEvents[T]) => void,
  ) => void;
  emit: (event: keyof ScanEvents, data: ScanEvents[keyof ScanEvents]) => void;
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
      findings: Finding[];
    }
  | {
      kind: "Error";
      error: string;
    };

export type ScanEstimateResult =
  | {
      kind: "Ok";
      checksTotal: number;
    }
  | {
      kind: "Error";
      error: string;
    };

export type ScanEvents = {
  "scan:started": unknown;
  "scan:finished": unknown;
  "scan:interrupted": { reason: InterruptReason };
  "scan:finding": {
    targetRequestID: string;
    checkID: string;
    finding: Finding;
  };
  "scan:check-started": { checkID: string; targetRequestID: string };
  "scan:check-finished": { checkID: string; targetRequestID: string };
  "scan:check-failed": {
    checkID: string;
    targetRequestID: string;
    errorCode: ScanRunnableErrorCode;
    errorMessage: string;
  };
  "scan:request-pending": {
    pendingRequestID: string;
    targetRequestID: string;
    checkID: string;
  };
  "scan:request-completed": {
    pendingRequestID: string;
    requestID: string;
    responseID: string;
    checkID: string;
    targetRequestID: string;
  };
  "scan:request-failed": {
    pendingRequestID: string;
    targetRequestID: string;
    checkID: string;
    error: string;
  };
};

export type ScanTarget = {
  request: Request;
  response?: Response;
};

export type RuntimeContext = {
  /** The target of the scan. This includes request and response. */
  target: ScanTarget;
  /** Access toCaido Backend SDK. */
  sdk: SDK;
  /** Runtime SDK for accessing utilities scoped to the current scan. */
  runtime: {
    /** Utilities for parsing HTML. */
    html: {
      /** Parse the HTML of a request. This returns a ParsedHtml which has DOM-like methods for querying the HTML. */
      parse: (requestID: string) => Promise<ParsedHtml>;
    };
    /** Access to the dependencies of the check. */
    dependencies: {
      /** Get a dependency by key. */
      get: (key: string) => JSONSerializable | undefined;
    };
  };
  /** The configuration of the scan. */
  config: ScanConfig;
};

export type StepExecutionRecord = {
  stepName: string;
  stateBefore: JSONSerializable;
  stateAfter: JSONSerializable;
  findings: Finding[];
} & ({ result: "done" } | { result: "continue"; nextStep: string });

export type CheckExecutionRecord = {
  checkId: string;
  targetRequestId: string;
  steps: StepExecutionRecord[];
} & (
  | {
      status: "completed";
      finalOutput: CheckOutput;
    }
  | {
      status: "failed";
      error: {
        code: ScanRunnableErrorCode;
        message: string;
      };
    }
);

export type ExecutionHistory = CheckExecutionRecord[];

export type ScanConfig = {
  aggressivity: ScanAggressivity;
  inScopeOnly: boolean;
  concurrentChecks: number;
  concurrentRequests: number;
  concurrentTargets: number;
  requestsDelayMs: number;
  scanTimeout: number;
  checkTimeout: number;
  severities: Severity[];
};
