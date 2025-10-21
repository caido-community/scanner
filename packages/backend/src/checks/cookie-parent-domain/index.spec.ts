import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import cookieParentDomainCheck from "./index";

describe("Cookie parent domain check", () => {
  it("flags cookies scoped to parent domain", async () => {
    const request = createMockRequest({
      id: "req-1",
      host: "app.example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "res-1",
      code: 200,
      headers: {
        "set-cookie": ["sessionId=abc123; Domain=.example.com; Path=/"],
      },
      body: "OK",
    });

    const executionHistory = await runCheck(cookieParentDomainCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(1);
    expect(findings[0]?.name).toBe("Cookie scoped to parent domain");
  });

  it("does not flag cookie scoped to exact host", async () => {
    const request = createMockRequest({
      id: "req-2",
      host: "app.example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "res-2",
      code: 200,
      headers: {
        "set-cookie": ["sessionId=abc123; Domain=app.example.com; Path=/"],
      },
      body: "OK",
    });

    const executionHistory = await runCheck(cookieParentDomainCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(0);
  });
});
