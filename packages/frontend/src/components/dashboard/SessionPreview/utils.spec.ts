import { Severity } from "engine";
import { describe, expect, it } from "vitest";

import { createSessionFindings } from "./utils";

const scanConfig = {
  aggressivity: "medium" as const,
  scopeIDs: [],
  concurrentChecks: 1,
  concurrentRequests: 1,
  concurrentTargets: 1,
  requestsDelayMs: 0,
  scanTimeout: 60,
  checkTimeout: 60,
  severities: ["info" as const],
};

describe("session preview utils", () => {
  it("flattens session findings with their request ids", () => {
    expect(
      createSessionFindings({
        kind: "Done",
        id: "ascan-1",
        title: "Example",
        createdAt: 1,
        startedAt: 2,
        finishedAt: 3,
        hasExecutionTrace: true,
        requestIDs: ["req-1"],
        scanConfig,
        progress: {
          checksTotal: 1,
          checksHistory: [
            {
              kind: "Completed",
              id: "execution-1",
              checkID: "open-redirect",
              targetRequestID: "req-1",
              startedAt: 2,
              completedAt: 3,
              requestsSent: [],
              findings: [
                {
                  name: "Open Redirect",
                  description: "Redirected to attacker controlled host.",
                  severity: Severity.HIGH,
                  correlation: {
                    requestID: "req-2",
                    locations: [],
                  },
                },
              ],
            },
          ],
        },
      }),
    ).toEqual([
      {
        id: "execution-1:0:req-2",
        name: "Open Redirect",
        description: "Redirected to attacker controlled host.",
        severity: Severity.HIGH,
        checkID: "open-redirect",
        checkStatus: "Completed",
        targetRequestID: "req-1",
        findingRequestID: "req-2",
      },
    ]);
  });

});
