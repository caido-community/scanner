import type { SDK } from "caido:plugin";
import { describe, expect, it } from "vitest";

import { createMockRequest } from "../__tests__/mocks/request";
import { createMockResponse } from "../__tests__/mocks/response";
import { createTestSdk } from "../__tests__/mocks/sdk";
import type { ScanConfig } from "../types/runner";
import { done } from "../utils/flow";

import { defineCheck } from "./define-check";
import { ScanRegistryErrorCode } from "./errors";
import { createRegistry } from "./registry";

const createSimpleCheck = (id: string, dependsOn?: string[]) => {
  return defineCheck<{ count: number }>(({ step }) => {
    step("execute", (state) => {
      return done({ state });
    });

    return {
      metadata: {
        id,
        name: id,
        description: `${id} description`,
        type: "passive",
        tags: [],
        severities: ["info"],
        aggressivity: {
          minRequests: 0,
          maxRequests: 0,
        },
        dependsOn,
      },
      initState: () => ({ count: 0 }),
      when: () => true,
    };
  });
};

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

describe("createRegistry", () => {
  it("throws when no checks are registered", () => {
    const registry = createRegistry();
    const sdk = createTestSdk();

    expect(() => {
      registry.create(sdk as unknown as SDK, createScanConfig());
    }).toThrowError(
      expect.objectContaining({
        code: ScanRegistryErrorCode.NO_CHECKS_REGISTERED,
      }),
    );
  });

  it("throws when check dependencies are missing", () => {
    const registry = createRegistry();
    registry.register(createSimpleCheck("consumer", ["provider"]));
    const sdk = createTestSdk();

    expect(() => {
      registry.create(sdk as unknown as SDK, createScanConfig());
    }).toThrowError(
      expect.objectContaining({
        code: ScanRegistryErrorCode.CHECK_DEPENDENCY_NOT_FOUND,
      }),
    );
  });

  it("creates runnable with valid dependencies", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
      query: "",
    });
    const response = createMockResponse({
      id: "1",
      code: 200,
      body: "ok",
    });
    const sdk = createTestSdk({
      requests: {
        "1": {
          request: {
            id: request.getId(),
            host: request.getHost(),
            port: request.getPort(),
            tls: request.getTls(),
            method: request.getMethod(),
            path: request.getPath(),
            query: request.getQuery(),
            headers: request.getHeaders(),
            body: request.getBody()?.toText(),
          },
          response: {
            id: response.getId(),
            code: response.getCode(),
            headers: response.getHeaders(),
            body: response.getBody()?.toText(),
            roundtripTime: response.getRoundtripTime(),
            createdAt: response.getCreatedAt(),
          },
        },
      },
    });

    const registry = createRegistry();
    registry.register(createSimpleCheck("provider"));
    registry.register(createSimpleCheck("consumer", ["provider"]));

    const runnable = registry.create(sdk as unknown as SDK, createScanConfig());
    const result = await runnable.run(["1"]);

    expect(result.kind).toBe("Finished");
  });
});
