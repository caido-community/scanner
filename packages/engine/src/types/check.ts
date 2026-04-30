import type { CheckAggressivity, CheckMetadata, CheckType } from "shared";

import { type Finding } from "./finding";
import { type RuntimeContext, type ScanTarget } from "./runner";
import { type JSONSerializable } from "./utils";

export type { CheckAggressivity, CheckMetadata, CheckType };

type CheckBase = {
  /** Metadata for the check. This contains all the information about the check. */
  metadata: CheckMetadata;
  /** Optional: Function that returns a unique key for the target. This is used to deduplicate findings. */
  dedupeKey?: (target: ScanTarget) => string;
  /** Optional: Function that returns a boolean indicating whether the check should run for the target. You can check here for example if the target method is POST. */
  when?: (target: ScanTarget) => boolean;
};

export type CheckSpec<T> = CheckBase & {
  /** Optional: Function that returns the initial state for the check. */
  initState?: () => T;
  /** Optional: Function that returns the output for the check. This is the data you return to dependencies. */
  output?: ({
    state,
    context,
  }: {
    state: T;
    context: RuntimeContext;
  }) => CheckOutput;
};

export type Check = CheckBase & {
  create: (context: RuntimeContext) => CheckTask;
};

export type CheckBuilder<T> = {
  step: (name: StepName, action: StepAction<T>) => void;
};

export type StepName = string;

export type StepResult<T> =
  | {
      kind: "Done";
      findings?: Finding[];
      state?: T;
    }
  | {
      kind: "Continue";
      nextStep: StepName;
      state: T;
      findings?: Finding[];
    };

export type StepAction<T> = (
  state: T,
  context: RuntimeContext,
) => Promise<StepResult<T>> | StepResult<T>;

export type Step<T> = {
  name: StepName;
  action: StepAction<T>;
};

export type StepTickResult = {
  status: "done" | "continue";
  findings?: Finding[];
};

export type CheckTask = {
  metadata: CheckMetadata;
  tick: () => Promise<StepTickResult>;
  getFindings: () => Finding[];
  getOutput: () => CheckOutput;
  getTarget: () => ScanTarget;
  getCurrentStepName: () => string | undefined;
  getCurrentState: () => JSONSerializable;
};

export type RunState<T> = {
  state: T;
  nextStep: StepName | undefined;
  findings: Finding[];
};

export type CheckOutput = JSONSerializable | undefined;
