import { type CheckOutput, type CheckTask } from "../types/check";
import { type Finding } from "../types/finding";
import {
  type InterruptReason,
  type ScanEvents,
  type StepExecutionRecord,
} from "../types/runner";

import {
  ScanRunnableError,
  ScanRunnableErrorCode,
  ScanRunnableInterruptedError,
} from "./errors";

type TaskExecutionResult =
  | {
      status: "done" | "continue";
      findings?: Finding[];
      output?: CheckOutput;
    }
  | {
      status: "failed";
      findings?: Finding[];
      errorCode: ScanRunnableErrorCode;
      errorMessage: string;
    };

type TaskExecutorOptions = {
  emit: <T extends keyof ScanEvents>(event: T, data: ScanEvents[T]) => void;
  getInterruptReason: () => InterruptReason | undefined;
  recordStepExecution: (record: StepExecutionRecord) => void;
};

type TaskExecutor = {
  tickUntilDone: (task: CheckTask) => Promise<TaskExecutionResult>;
};

export const createTaskExecutor = ({
  emit,
  getInterruptReason,
  recordStepExecution,
}: TaskExecutorOptions): TaskExecutor => {
  const tick = async (task: CheckTask): Promise<TaskExecutionResult> => {
    const interruptReason = getInterruptReason();
    if (interruptReason) {
      throw new ScanRunnableInterruptedError(interruptReason);
    }

    try {
      const stateBefore = task.getCurrentState();
      const currentStepName = task.getCurrentStepName() ?? "unknown";

      const result = await task.tick();

      const stateAfter = task.getCurrentState();
      const nextStepName = task.getCurrentStepName();

      if (result.findings) {
        for (const finding of result.findings) {
          emit("scan:finding", {
            targetRequestID: task.getTarget().request.getId(),
            checkID: task.metadata.id,
            finding,
          });
        }
      }

      const stepRecord: StepExecutionRecord = {
        stepName: currentStepName,
        stateBefore,
        stateAfter,
        findings: result.findings || [],
        ...(result.status === "done"
          ? { result: "done" }
          : { result: "continue", nextStep: nextStepName ?? "unknown" }),
      };

      recordStepExecution(stepRecord);

      return {
        findings: result.findings,
        status: result.status,
        output: result.status === "done" ? task.getOutput() : undefined,
      };
    } catch (error) {
      if (error instanceof ScanRunnableInterruptedError) {
        throw error;
      }
      if (error instanceof ScanRunnableError) {
        return {
          findings: [],
          status: "failed",
          errorCode: error.code,
          errorMessage: error.message,
        };
      }

      return {
        findings: [],
        status: "failed",
        errorCode: ScanRunnableErrorCode.UNKNOWN_CHECK_ERROR,
        errorMessage:
          error instanceof Error ? error.message : "Unknown error occurred",
      };
    }
  };

  const tickUntilDone = async (
    task: CheckTask,
  ): Promise<TaskExecutionResult> => {
    const allFindings: Finding[] = [];

    while (true) {
      const result = await tick(task);

      if (result.findings) {
        allFindings.push(...result.findings);
      }

      if (result.status === "continue") {
        continue;
      }

      if (result.status === "done") {
        return {
          findings: allFindings,
          status: "done",
          output: result.output,
        };
      }

      if (result.status === "failed") {
        return {
          findings: allFindings,
          status: "failed",
          errorCode: result.errorCode,
          errorMessage: result.errorMessage,
        };
      }

      throw new Error(
        "Invalid status, you shouldn't ever reach this point. Please report this as a bug.",
      );
    }
  };

  return {
    tickUntilDone,
  };
};
