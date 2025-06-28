import type { Finding } from "./finding";
import type { CheckContext } from "./runner";
import type { JSONSerializable } from "./utils";

export type DefineUtils<T> = {
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
  context: CheckContext,
) => Promise<StepResult<T>> | StepResult<T>;

export type Step<T> = {
  name: StepName;
  action: StepAction<T>;
};

export type StepTickResult = {
  isDone: boolean;
  findings?: Finding[];
};

export type ScanTask = {
  id: string;
  tick: () => Promise<StepTickResult>;
  getFindings: () => Finding[];
  serialize: () => string;
  getOutput: () => JSONSerializable | undefined;
};

export type RunState<T> = {
  state: T;
  nextStep: StepName;
  findings: Finding[];
};
