import { describe, expect, it } from "vitest";

import {
  createExecutionIndexKey,
  hasSessionProgress,
  recoverSession,
} from "./scanner.utils";

describe("scanner utils", () => {
  it("creates stable execution index keys", () => {
    expect(
      createExecutionIndexKey({
        sessionId: "session",
        checkId: "check",
        targetId: "target",
      }),
    ).toBe("session:check:target");
  });

  it("recovers pending sessions as interrupted runtime stopped", () => {
    expect(
      recoverSession({
        kind: "Pending",
        id: "session",
        createdAt: 1,
        title: "Pending",
        requestIDs: [],
        scanConfig: {
          aggressivity: "medium",
          scopeIDs: [],
          concurrentChecks: 1,
          concurrentRequests: 1,
          concurrentTargets: 1,
          requestsDelayMs: 0,
          scanTimeout: 60,
          checkTimeout: 60,
          severities: ["info"],
        },
      }),
    ).toEqual(
      expect.objectContaining({
        kind: "Interrupted",
        reason: "RuntimeStopped",
        hasExecutionTrace: false,
      }),
    );
  });

  it("identifies sessions with progress", () => {
    expect(
      hasSessionProgress({
        kind: "Error",
        id: "session",
        createdAt: 1,
        title: "Error",
        error: "boom",
        hasExecutionTrace: false,
        requestIDs: [],
        scanConfig: {
          aggressivity: "medium",
          scopeIDs: [],
          concurrentChecks: 1,
          concurrentRequests: 1,
          concurrentTargets: 1,
          requestsDelayMs: 0,
          scanTimeout: 60,
          checkTimeout: 60,
          severities: ["info"],
        },
      }),
    ).toBe(false);
  });
});
