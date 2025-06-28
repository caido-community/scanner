import type { CheckContext, CheckTarget, ScanStrength } from "./runner";
import type { ScanTask as CheckTask } from "./task";

export type CheckAggressivity = {
  minRequests: number;
  maxRequests: number | "Infinity";
};

export type CheckType = "passive" | "active";
export type CheckMetadata = {
  id: string;
  name: string;
  description: string;
  tags: string[];
  aggressivity: CheckAggressivity;
  type: CheckType;
  dependsOn?: string[];
  minStrength?: ScanStrength;
};

export type CheckDefinition = {
  metadata: CheckMetadata;
  dedupeKey?: (context: CheckTarget) => string;
  when?: (context: CheckContext) => boolean;
  create: (context: CheckContext) => CheckTask;
};
