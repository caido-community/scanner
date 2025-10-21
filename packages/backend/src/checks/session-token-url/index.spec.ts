import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import sessionTokenCheck from "./index";

describe("Session token in URL check", () => {
  it("detects session identifier in query string", async () => {
    const request = createMockRequest({
      id: "req-1",
      host: "example.com",
      method: "GET",
      path: "/app",
      query: "sessionid=abcdef1234567890&lang=en",
    });

    const response = createMockResponse({
      id: "res-1",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "OK",
    });

    const executionHistory = await runCheck(sessionTokenCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "session-token-in-url",
        targetRequestId: "req-1",
        status: "completed",
        steps: [
          {
            stepName: "detectSessionTokens",
            findings: [
              {
                name: "Session token disclosed in URL",
                severity: "high",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("detects tokens embedded in the path", async () => {
    const request = createMockRequest({
      id: "req-2",
      host: "example.com",
      method: "GET",
      path: "/app;jsessionid=ABCDEF1234567890/dashboard",
      query: "",
    });

    const response = createMockResponse({
      id: "res-2",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "OK",
    });

    const executionHistory = await runCheck(sessionTokenCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.description).toContain("path");
  });

  it("ignores non-sensitive parameters", async () => {
    const request = createMockRequest({
      id: "req-3",
      host: "example.com",
      method: "GET",
      path: "/app",
      query: "page=home&sid=123", // sid is short, should not trigger
    });

    const response = createMockResponse({
      id: "res-3",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "OK",
    });

    const executionHistory = await runCheck(sessionTokenCheck, [
      { request, response },
    ]);

    const lastStep =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1];
    expect(lastStep?.findings ?? []).toHaveLength(0);
  });
});
