import type { CheckType, ScanAggressivity } from "./scan";
import type { Severity } from "./severity";

export type CheckAggressivity = {
  minRequests: number;
  maxRequests: number | "Infinity";
};

export type CheckMetadata = {
  id: string;
  name: string;
  description: string;
  tags: string[];
  aggressivity: CheckAggressivity;
  type: CheckType;
  severities: Severity[];
  dependsOn?: string[];
  minAggressivity?: ScanAggressivity;
  skipIfFoundBy?: string[];
};
