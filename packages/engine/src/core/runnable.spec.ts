import { describe, expect, it } from "vitest";

import { createMockRequest } from "../__tests__/mocks/request";
import { createTestSdk } from "../__tests__/mocks/sdk";
import type { Check, RuntimeContext } from "../types";
import { done } from "../utils/flow";

import { defineCheck } from "./define-check";
import { createRegistry } from "./registry";
import { evaluateCheckApplicability, getCheckBatches } from "./runnable";

const createCheck = (options: {
  id: string;
  severities?: Array<"info" | "low" | "medium" | "high" | "critical">;
  dependsOn?: string[];
  minAggressivity?: "low" | "medium" | "high";
  dedupeKey?: (target: RuntimeContext["target"]) => string;
  when?: (target: RuntimeContext["target"]) => boolean;
}): Check => {
  return defineCheck<{ count: number }>(({ step }) => {
    step("execute", (state) => done({ state }));

    return {
      metadata: {
        id: options.id,
        name: options.id,
        description: options.id,
        type: "passive",
        tags: [],
        severities: options.severities ?? ["info"],
        aggressivity: {
          minRequests: 0,
          maxRequests: 0,
        },
        dependsOn: options.dependsOn,
        minAggressivity: options.minAggressivity,
      },
      initState: () => ({ count: 0 }),
      dedupeKey: options.dedupeKey,
      when: options.when,
    };
  });
};

const createRuntimeContext = (): RuntimeContext => {
  const sdk = createTestSdk() as unknown as RuntimeContext["sdk"];
  const request = createMockRequest({
    id: "1",
    host: "example.com",
    method: "GET",
    path: "/",
    query: "foo=bar",
  });

  return {
    target: { request, response: undefined },
    sdk,
    config: {
      aggressivity: "medium",
      scopeIDs: [],
      concurrentChecks: 1,
      concurrentRequests: 1,
      concurrentTargets: 1,
      requestsDelayMs: 0,
      scanTimeout: 60,
      checkTimeout: 60,
      severities: ["info", "low", "medium", "high", "critical"],
    },
    runtime: {
      html: {
        parse: () => Promise.reject(new Error("unused")),
      },
      dependencies: {
        get: () => undefined,
      },
    },
  };
};

describe("evaluateCheckApplicability", () => {
  it("filters out checks by severity and aggressivity", () => {
    const context = createRuntimeContext();
    const lowSeverityCheck = createCheck({
      id: "severity-check",
      severities: ["critical"],
    });

    const lowAggressivityCheck = createCheck({
      id: "aggressivity-check",
      minAggressivity: "high",
    });

    expect(
      evaluateCheckApplicability({
        check: lowSeverityCheck,
        context: {
          ...context,
          config: { ...context.config, severities: ["low"] },
        },
        dedupeKeys: new Map(),
      }),
    ).toEqual({ kind: "Error", error: "severity" });

    expect(
      evaluateCheckApplicability({
        check: lowAggressivityCheck,
        context,
        dedupeKeys: new Map(),
      }),
    ).toEqual({ kind: "Error", error: "aggressivity" });
  });

  it("respects check when predicate", () => {
    const context = createRuntimeContext();
    const check = createCheck({
      id: "when-check",
      when: () => false,
    });

    expect(
      evaluateCheckApplicability({
        check,
        context,
        dedupeKeys: new Map(),
      }),
    ).toEqual({ kind: "Error", error: "when" });
  });

  it("returns dedupe record only when key is new", () => {
    const context = createRuntimeContext();
    const check = createCheck({
      id: "dedupe-check",
      dedupeKey: (target) => target.request.getHost(),
    });

    const dedupeKeys = new Map<string, Set<string>>();
    dedupeKeys.set("dedupe-check", new Set(["example.com"]));

    expect(
      evaluateCheckApplicability({
        check,
        context,
        dedupeKeys,
      }),
    ).toEqual({ kind: "Error", error: "duplicate-dedupe-key" });

    const emptyDedupe = new Map<string, Set<string>>();
    expect(
      evaluateCheckApplicability({
        check,
        context,
        dedupeKeys: emptyDedupe,
      }),
    ).toEqual({
      kind: "Ok",
      value: {
        dedupeRecord: {
          checkID: "dedupe-check",
          key: "example.com",
        },
      },
    });
  });
});

describe("getCheckBatches", () => {
  it("topologically orders checks by dependencies", () => {
    const provider = createCheck({ id: "provider" });
    const consumer = createCheck({ id: "consumer", dependsOn: ["provider"] });
    const independent = createCheck({ id: "independent" });

    const batches = getCheckBatches([consumer, provider, independent]);
    const batchIDs = batches.map((batch) =>
      batch.map((check) => check.metadata.id),
    );

    expect(batchIDs[0]).toContain("provider");
    expect(batchIDs[batchIDs.length - 1]).toContain("consumer");
    expect(batchIDs.flat()).toEqual(
      expect.arrayContaining(["provider", "consumer", "independent"]),
    );
  });

  it("throws for unknown dependencies", () => {
    const check = createCheck({ id: "consumer", dependsOn: ["missing"] });

    expect(() => getCheckBatches([check])).toThrow(
      "Check 'consumer' has unknown dependency 'missing'",
    );
  });
});

describe("createRunnable", () => {
  it("returns an interrupted timeout result when the scan timeout fires", async () => {
    const check = defineCheck<{ complete: boolean }>(({ step }) => {
      step("execute", async (state) => {
        await new Promise((resolve) => setTimeout(resolve, 25));

        return done({
          state: {
            ...state,
            complete: true,
          },
        });
      });

      return {
        metadata: {
          id: "slow-check",
          name: "slow-check",
          description: "slow-check",
          type: "passive",
          tags: [],
          severities: ["info"],
          aggressivity: {
            minRequests: 0,
            maxRequests: 0,
          },
        },
        initState: () => ({ complete: false }),
      };
    });
    const registry = createRegistry();
    registry.register(check);

    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
      query: "",
    });
    const sdk = createTestSdk({
      requests: {
        [request.getId()]: {
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
        },
      },
    });
    const runnable = registry.create(sdk as unknown as RuntimeContext["sdk"], {
      aggressivity: "medium",
      scopeIDs: [],
      concurrentChecks: 1,
      concurrentRequests: 1,
      concurrentTargets: 1,
      requestsDelayMs: 0,
      scanTimeout: 0.01,
      checkTimeout: 1,
      severities: ["info", "low", "medium", "high", "critical"],
    });

    const result = await runnable.run([request.getId()]);

    expect(result).toEqual({
      kind: "Interrupted",
      reason: "Timeout",
      findings: [],
    });
  });
});
