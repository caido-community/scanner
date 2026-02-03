import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import timeBasedSQLI from "./index";

describe("Time-Based SQL Injection", () => {
  it("should run when parameters exist and response is present", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/test",
      query: "id=1",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "Response body",
      roundtripTime: 100,
    });

    const executionHistory = await runCheck(timeBasedSQLI, [
      { request, response },
    ]);

    expect(executionHistory.length).toBe(1);
    const record = executionHistory[0]!;
    expect(record.checkId).toBe("time-based-sqli");
    expect(record.status).toBe("completed");
    expect(record.steps.length).toBeGreaterThan(0);
    expect(record.steps[0]!.stepName).toBe("measureBaseline");
  });

  it("should not run when there are no parameters", async () => {
    const request = createMockRequest({
      id: "2",
      host: "example.com",
      method: "GET",
      path: "/test",
    });

    const response = createMockResponse({
      id: "2",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "Response body",
    });

    const executionHistory = await runCheck(timeBasedSQLI, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([]);
  });

  it("should have correct metadata", () => {
    expect(timeBasedSQLI.metadata.id).toBe("time-based-sqli");
    expect(timeBasedSQLI.metadata.name).toBe("Time-Based SQL Injection");
    expect(timeBasedSQLI.metadata.type).toBe("active");
    expect(timeBasedSQLI.metadata.severities).toContain("critical");
    expect(timeBasedSQLI.metadata.description).toContain("MySQL");
    expect(timeBasedSQLI.metadata.description).toContain("PostgreSQL");
  });

  it("should have payloads for supported databases", () => {
    expect(timeBasedSQLI.metadata.aggressivity.maxRequests).toBe(8);
  });
});
