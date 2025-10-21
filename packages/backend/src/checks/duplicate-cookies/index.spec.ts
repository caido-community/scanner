import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import duplicateCookiesCheck from "./index";

describe("Duplicate cookies check", () => {
  it("detects duplicate cookie names", async () => {
    const request = createMockRequest({
      id: "req-1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "res-1",
      code: 200,
      headers: {
        "set-cookie": [
          "sessionId=abc123; Path=/; HttpOnly",
          "SessionID=def456; Path=/; Secure",
          "lang=en",
        ],
      },
      body: "OK",
    });

    const executionHistory = await runCheck(duplicateCookiesCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(1);
    expect(findings[0]?.name).toBe("Duplicate cookies set");
    expect(findings[0]?.description).toContain("sessionid");
  });

  it("ignores unique cookie names", async () => {
    const request = createMockRequest({
      id: "req-2",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "res-2",
      code: 200,
      headers: {
        "set-cookie": ["sessionId=abc123", "lang=en"],
      },
      body: "OK",
    });

    const executionHistory = await runCheck(duplicateCookiesCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(0);
  });
});
