import type { SDK } from "caido:plugin";
import { describe, expect, it } from "vitest";

import { createMockRequest } from "../__tests__/mocks/request";
import { createMockRequestSpec } from "../__tests__/mocks/request-spec";
import { createMockResponse } from "../__tests__/mocks/response";
import { createTestSdk } from "../__tests__/mocks/sdk";
import type { ScanConfig, ScanEvents } from "../types/runner";

import { ScanRunnableErrorCode, ScanRunnableInterruptedError } from "./errors";
import {
  canStartQueuedRequest,
  computeDelayNeeded,
  createRequestQueue,
} from "./request-queue";

const createScanConfig = (): ScanConfig => ({
  aggressivity: "medium" as const,
  scopeIDs: [],
  concurrentChecks: 1,
  concurrentRequests: 1,
  concurrentTargets: 1,
  requestsDelayMs: 0,
  scanTimeout: 60,
  checkTimeout: 60,
  severities: ["info", "low", "medium", "high", "critical"],
});

describe("createRequestQueue", () => {
  it("processes requests and emits completion events", async () => {
    let counter = 0;
    const sdk = createTestSdk({
      sendHandler: (spec) => {
        counter += 1;
        const request = createMockRequest({
          id: `req-${counter}`,
          host: spec.getHost(),
          port: spec.getPort(),
          tls: spec.getTls(),
          method: spec.getMethod(),
          path: spec.getPath(),
          query: spec.getQuery(),
          headers: spec.getHeaders(),
          body: spec.getBody()?.toText(),
        });
        const response = createMockResponse({
          id: `res-${counter}`,
          code: 200,
          body: "ok",
        });
        return Promise.resolve({ request, response });
      },
    });

    const completedEvents: ScanEvents["scan:request-completed"][] = [];
    const queue = createRequestQueue({
      sdk: sdk as unknown as SDK,
      config: createScanConfig(),
      emit: (event, data) => {
        if (event === "scan:request-completed") {
          completedEvents.push(data as ScanEvents["scan:request-completed"]);
        }
      },
      getInterruptReason: () => undefined,
    });

    const result = await queue.enqueue(
      createMockRequestSpec({ host: "example.com", query: "x=1" }),
      "pending-1",
      "target-1",
      "check-1",
    );

    expect(result.request.getId()).toBe("req-1");
    expect(completedEvents).toEqual([
      {
        pendingRequestID: "pending-1",
        requestID: "req-1",
        responseID: "res-1",
        checkID: "check-1",
        targetRequestID: "target-1",
      },
    ]);
  });

  it("emits failure events and wraps transport errors", async () => {
    const sdk = createTestSdk({
      sendHandler: () => {
        return Promise.reject(new Error("network-failure"));
      },
    });

    const failedEvents: ScanEvents["scan:request-failed"][] = [];
    const queue = createRequestQueue({
      sdk: sdk as unknown as SDK,
      config: createScanConfig(),
      emit: (event, data) => {
        if (event === "scan:request-failed") {
          failedEvents.push(data as ScanEvents["scan:request-failed"]);
        }
      },
      getInterruptReason: () => undefined,
    });

    await expect(
      queue.enqueue(
        createMockRequestSpec({ host: "example.com", query: "x=1" }),
        "pending-1",
        "target-1",
        "check-1",
      ),
    ).rejects.toEqual(
      expect.objectContaining({
        code: ScanRunnableErrorCode.REQUEST_FAILED,
      }),
    );

    expect(failedEvents).toEqual([
      {
        pendingRequestID: "pending-1",
        error: "network-failure",
        targetRequestID: "target-1",
        checkID: "check-1",
      },
    ]);
  });

  it("uses requestTimeout when provided, falls back to checkTimeout", async () => {
    const sdk = createTestSdk({
      sendHandler: () => new Promise(() => {}),
    });

    const configWithRequestTimeout = {
      ...createScanConfig(),
      checkTimeout: 60,
      requestTimeout: 1,
    };

    const queue = createRequestQueue({
      sdk: sdk as unknown as SDK,
      config: configWithRequestTimeout,
      emit: () => {},
      getInterruptReason: () => undefined,
    });

    await expect(
      queue.enqueue(
        createMockRequestSpec({ host: "example.com" }),
        "pending-1",
        "target-1",
        "check-1",
      ),
    ).rejects.toThrow("Request timeout after 1 seconds");
  });

  it("rejects with interruption when scan is interrupted", async () => {
    const sdk = createTestSdk();
    let interrupt: "Cancelled" | "Timeout" | undefined = "Cancelled";

    const queue = createRequestQueue({
      sdk: sdk as unknown as SDK,
      config: createScanConfig(),
      emit: () => {},
      getInterruptReason: () => interrupt,
    });

    await expect(
      queue.enqueue(
        createMockRequestSpec({ host: "example.com" }),
        "pending-1",
        "target-1",
        "check-1",
      ),
    ).rejects.toBeInstanceOf(ScanRunnableInterruptedError);

    interrupt = undefined;
  });
});

describe("request queue pure helpers", () => {
  it("computes delay correctly", () => {
    expect(
      computeDelayNeeded({
        now: 200,
        lastRequestTime: 100,
        requestsDelayMs: 150,
      }),
    ).toBe(50);
    expect(
      computeDelayNeeded({
        now: 300,
        lastRequestTime: 100,
        requestsDelayMs: 150,
      }),
    ).toBe(0);
  });

  it("decides when queued request can start", () => {
    expect(
      canStartQueuedRequest({
        queueLength: 1,
        activeRequests: 0,
        concurrentRequests: 1,
      }),
    ).toBe(true);

    expect(
      canStartQueuedRequest({
        queueLength: 0,
        activeRequests: 0,
        concurrentRequests: 1,
      }),
    ).toBe(false);

    expect(
      canStartQueuedRequest({
        queueLength: 2,
        activeRequests: 1,
        concurrentRequests: 1,
      }),
    ).toBe(false);
  });
});
