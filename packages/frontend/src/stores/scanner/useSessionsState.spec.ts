import { describe, expect, it } from "vitest";

import { useSessionsState } from "./useSessionsState";

const session = {
  kind: "Pending" as const,
  id: "ascan-1",
  createdAt: 1,
  title: "Example",
  requestIDs: ["req-1"],
  scanConfig: {
    aggressivity: "medium" as const,
    scopeIDs: [],
    concurrentChecks: 1,
    concurrentRequests: 1,
    concurrentTargets: 1,
    requestsDelayMs: 0,
    scanTimeout: 60,
    checkTimeout: 60,
    severities: ["info" as const],
  },
};

describe("useSessionsState", () => {
  it("upserts a session when receiving an update for an unknown session", () => {
    const store = useSessionsState();

    store.send({ type: "Start" });
    store.send({ type: "Success", sessions: [] });
    store.send({
      type: "UpdateSession",
      session: {
        ...session,
        kind: "Error",
        error: "Request req-1 not found",
        hasExecutionTrace: false,
      },
    });

    expect(store.getState()).toEqual({
      type: "Success",
      sessions: [
        {
          ...session,
          kind: "Error",
          error: "Request req-1 not found",
          hasExecutionTrace: false,
        },
      ],
    });
  });

  it("clears loading state back to idle", () => {
    const store = useSessionsState();

    store.send({ type: "Start" });
    store.send({ type: "Clear" });

    expect(store.getState()).toEqual({ type: "Idle" });
  });
});
