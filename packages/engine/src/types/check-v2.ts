import type { Request, RequestSpec, Response } from "caido:utils";

import type { CheckAggressivity, CheckOutput, CheckType } from "./check";
import type { Severity } from "./finding";
import type { Result } from "./result";
import type { RuntimeContext, ScanAggressivity, ScanTarget } from "./runner";

export type CheckDefinitionV2 = {
  id: string;
  name: string;
  description: string;
  type: CheckType;
  tags: string[];
  severities: Severity[];
  aggressivity: CheckAggressivity;
  dependsOn?: string[];
  minAggressivity?: ScanAggressivity;
  skipIfFoundBy?: string[];

  dedupeKey?: (target: ScanTarget) => string;
  when?: (target: ScanTarget) => boolean;
  output?: (ctx: CheckContext) => CheckOutput;
  execute: (ctx: CheckContext) => Promise<void>;
};

export type CheckContext = RuntimeContext & {
  send: (spec: RequestSpec) => Promise<Result<SendOk, SendErr>>;
  finding: (input: FindingInput) => void;
  parameters: (opts?: { reflected?: boolean }) => Parameter[];
  limit: <T>(items: T[], limits: AggressivityLimits) => T[];
  interrupted: boolean;
  target: TargetAccessor;
};

export type TargetAccessor = ScanTarget & {
  hasParameters: () => boolean;
  hasBody: () => boolean;
  isMethod: (...methods: string[]) => boolean;
  header: (name: string) => string | undefined;
  bodyText: () => string | undefined;
};

export type Parameter = {
  name: string;
  value: string;
  source: "query" | "body" | "header";
  inject: (newValue: string) => RequestSpec;
};

export type SendOk = {
  request: Request;
  response: Response;
};

export type SendErr = {
  request?: Request;
  error: string;
};

export type FindingInput = {
  name: string;
  severity: Severity;
  description: string;
  request?: Request;
  impact?: string;
  recommendation?: string;
  artifacts?: { title: string; items: string[] };
};

export type AggressivityLimits = {
  low: number;
  medium: number;
  high: number;
};

export type RegexCheckDefinition = {
  id: string;
  name: string;
  description: string;
  tags: string[];
  severity: Severity;
  patterns: RegExp[];

  dedupeKey?: (target: ScanTarget) => string;
  when?: (target: ScanTarget) => boolean;
  toFinding: (matches: string[]) => { name: string; description: string };
};
