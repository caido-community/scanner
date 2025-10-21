import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import aspNetTracingCheck from "./index";

describe("ASP.NET tracing check", () => {
  it("detects trace.axd output", async () => {
    const request = createMockRequest({
      id: "req-1",
      host: "example.com",
      method: "GET",
      path: "/trace.axd",
    });

    const response = createMockResponse({
      id: "res-1",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "<html><title>Trace Information</title><body>Request Details</body></html>",
    });

    const executionHistory = await runCheck(aspNetTracingCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(1);
    expect(findings[0]?.name).toBe("ASP.NET tracing enabled");
  });

  it("ignores non-trace responses", async () => {
    const request = createMockRequest({
      id: "req-2",
      host: "example.com",
      method: "GET",
      path: "/trace.axd",
    });

    const response = createMockResponse({
      id: "res-2",
      code: 404,
      headers: { "content-type": ["text/html"] },
      body: "Not found",
    });

    const executionHistory = await runCheck(aspNetTracingCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(0);
  });
});
