import { type CheckOutput } from "../../types/check";
import {
  type CheckExecutionRecord,
  type ExecutionHistory,
  type StepExecutionRecord,
} from "../../types/runner";
import { type ScanRunnableErrorCode } from "../errors";

type ActiveCheckRecord = {
  checkId: string;
  targetRequestId: string;
  steps: StepExecutionRecord[];
};

const createCheckRecordKey = ({
  checkId,
  targetRequestId,
}: {
  checkId: string;
  targetRequestId: string;
}): string => `${checkId}-${targetRequestId}`;

/**
 * Creates the execution history recorder used by a runnable scan.
 *
 * The runnable calls this to track each check as it starts, records step progress,
 * and stores the final completed or failed history entries that tests and callers
 * can read later through `getHistory()`.
 */
export const createExecutionHistoryRecorder = () => {
  const executionHistory: ExecutionHistory = [];
  const activeCheckRecords = new Map<string, ActiveCheckRecord>();

  const start = ({
    checkId,
    targetRequestId,
  }: {
    checkId: string;
    targetRequestId: string;
  }) => {
    activeCheckRecords.set(
      createCheckRecordKey({
        checkId,
        targetRequestId,
      }),
      {
        checkId,
        targetRequestId,
        steps: [],
      },
    );
  };

  const drop = ({
    checkId,
    targetRequestId,
  }: {
    checkId: string;
    targetRequestId: string;
  }) => {
    activeCheckRecords.delete(
      createCheckRecordKey({
        checkId,
        targetRequestId,
      }),
    );
  };

  const recordStep = ({
    checkId,
    targetRequestId,
    record,
  }: {
    checkId: string;
    targetRequestId: string;
    record: StepExecutionRecord;
  }) => {
    const activeRecord = activeCheckRecords.get(
      createCheckRecordKey({
        checkId,
        targetRequestId,
      }),
    );

    if (activeRecord !== undefined) {
      activeRecord.steps.push(record);
    }
  };

  const complete = ({
    checkId,
    targetRequestId,
    finalOutput,
  }: {
    checkId: string;
    targetRequestId: string;
    finalOutput: CheckOutput;
  }) => {
    const key = createCheckRecordKey({
      checkId,
      targetRequestId,
    });
    const activeRecord = activeCheckRecords.get(key);
    if (activeRecord === undefined) {
      return;
    }

    const checkRecord: CheckExecutionRecord = {
      checkId: activeRecord.checkId,
      targetRequestId: activeRecord.targetRequestId,
      steps: activeRecord.steps,
      status: "completed",
      finalOutput,
    };

    executionHistory.push(checkRecord);
    activeCheckRecords.delete(key);
  };

  const fail = ({
    checkId,
    targetRequestId,
    errorCode,
    errorMessage,
  }: {
    checkId: string;
    targetRequestId: string;
    errorCode: ScanRunnableErrorCode;
    errorMessage: string;
  }) => {
    const key = createCheckRecordKey({
      checkId,
      targetRequestId,
    });
    const activeRecord = activeCheckRecords.get(key);
    if (activeRecord === undefined) {
      return;
    }

    const checkRecord: CheckExecutionRecord = {
      checkId: activeRecord.checkId,
      targetRequestId: activeRecord.targetRequestId,
      steps: activeRecord.steps,
      status: "failed",
      error: {
        code: errorCode,
        message: errorMessage,
      },
    };

    executionHistory.push(checkRecord);
    activeCheckRecords.delete(key);
  };

  return {
    start,
    drop,
    recordStep,
    complete,
    fail,
    getHistory: () => [...executionHistory],
  };
};
