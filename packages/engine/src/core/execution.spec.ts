import { describe, expect, it } from "vitest";

import { createMockRequest } from "../__tests__/mocks/request";
import type { CheckTask, StepTickResult } from "../types/check";
import type { Finding } from "../types/finding";

import {
  ScanRunnableError,
  ScanRunnableErrorCode,
  ScanRunnableInterruptedError,
} from "./errors";
import { createTaskExecutor } from "./execution";

const createFinding = (requestID: string): Finding => ({
  name: "finding",
  description: "desc",
  severity: "low",
  correlation: {
    requestID,
    locations: [],
  },
});

const createTask = (options: {
  results?: StepTickResult[];
  throwOnTick?: Error;
}): CheckTask => {
  const request = createMockRequest({
    id: "1",
    host: "example.com",
    method: "GET",
    path: "/",
  });
  const results = options.results ?? [{ status: "done", findings: [] }];
  let cursor = 0;
  let currentState = { cursor: 0 };
  let currentStepName = "step-1";

  return {
    metadata: {
      id: "test-check",
      name: "test-check",
      description: "test-check",
      tags: [],
      aggressivity: {
        minRequests: 0,
        maxRequests: 0,
      },
      type: "passive",
      severities: ["info", "low", "medium", "high", "critical"],
    },
    tick: () => {
      if (options.throwOnTick !== undefined) {
        return Promise.reject(options.throwOnTick);
      }

      const result = results[cursor] ?? { status: "done", findings: [] };
      cursor += 1;
      currentState = { cursor };
      currentStepName = result.status === "continue" ? "step-2" : "done";
      return Promise.resolve(result);
    },
    getFindings: () => [],
    getOutput: () => ({ ok: true }),
    getTarget: () => ({ request, response: undefined }),
    getCurrentStepName: () => currentStepName,
    getCurrentState: () => currentState,
  };
};

describe("createTaskExecutor", () => {
  it("collects findings across continue ticks", async () => {
    const finding = createFinding("1");
    const emitted: string[] = [];
    const records: string[] = [];
    const task = createTask({
      results: [
        { status: "continue", findings: [finding] },
        { status: "done", findings: [finding] },
      ],
    });

    const executor = createTaskExecutor({
      emit: (event) => emitted.push(event),
      getInterruptReason: () => undefined,
      recordStepExecution: (record) => records.push(record.stepName),
    });

    const result = await executor.tickUntilDone(task);

    expect(result.status).toBe("done");
    if (result.status === "done") {
      expect(result.findings).toHaveLength(2);
    }
    expect(emitted.filter((event) => event === "scan:finding")).toHaveLength(2);
    expect(records).toHaveLength(2);
  });

  it("returns failed result for ScanRunnableError", async () => {
    const task = createTask({
      throwOnTick: new ScanRunnableError(
        "boom",
        ScanRunnableErrorCode.RUNTIME_ERROR,
      ),
    });

    const executor = createTaskExecutor({
      emit: () => {},
      getInterruptReason: () => undefined,
      recordStepExecution: () => {},
    });

    const result = await executor.tickUntilDone(task);

    expect(result).toEqual({
      status: "failed",
      findings: [],
      errorCode: ScanRunnableErrorCode.RUNTIME_ERROR,
      errorMessage: "boom",
    });
  });

  it("throws interruption when interrupt reason is set", async () => {
    const task = createTask({});
    const executor = createTaskExecutor({
      emit: () => {},
      getInterruptReason: () => "Cancelled",
      recordStepExecution: () => {},
    });

    await expect(executor.tickUntilDone(task)).rejects.toBeInstanceOf(
      ScanRunnableInterruptedError,
    );
  });
});
