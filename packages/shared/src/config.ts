import type { CheckType, ScanAggressivity } from "./scan";
import type { Severity } from "./severity";

export type Override = {
  enabled: boolean;
  checkID: string;
};

export type PassiveConfig = {
  enabled: boolean;
  aggressivity: ScanAggressivity;
  scopeIDs: string[];
  concurrentTargets: number;
  concurrentRequests: number;
  overrides: Override[];
  severities: Severity[];
};

export type ActiveConfig = {
  overrides: Override[];
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
  requestTimeout?: number;
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
