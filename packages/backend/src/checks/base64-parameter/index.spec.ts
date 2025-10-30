import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import base64ParameterCheck from "./index";

describe("Base64 parameter check", () => {
  it("detects base64 encoded query parameter", async () => {
    const request = createMockRequest({
      id: "req-1",
      host: "example.com",
      method: "GET",
      path: "/api",
      query: "token=YWJjZGVmZ2hpamtsbW5vcA==",
    });

    const response = createMockResponse({
      id: "res-1",
      code: 200,
      headers: { "content-type": ["text/plain"] },
      body: "OK",
    });

    const executionHistory = await runCheck(base64ParameterCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(1);
    expect(findings[0]?.name).toBe("Base64 encoded data in parameter");
  });

  it("ignores short strings", async () => {
    const request = createMockRequest({
      id: "req-2",
      host: "example.com",
      method: "GET",
      path: "/api",
      query: "token=YWJj",
    });

    const response = createMockResponse({
      id: "res-2",
      code: 200,
      headers: { "content-type": ["text/plain"] },
      body: "OK",
    });

    const executionHistory = await runCheck(base64ParameterCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(0);
  });
});
