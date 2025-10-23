import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import hstsCheck from "./index";

const executeCheck = async (config: {
  tls: boolean;
  header?: string[];
}): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "req-hsts",
    host: "example.com",
    method: "GET",
    path: "/",
    tls: config.tls,
    headers: { Host: ["example.com"] },
  });

  const headers: Record<string, string[]> = {};
  if (config.header !== undefined) {
    headers["strict-transport-security"] = config.header;
  }

  const response = createMockResponse({
    id: "res-hsts",
    code: 200,
    headers,
    body: "",
  });

  const execution = await runCheck(hstsCheck, [{ request, response }]);
  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("HSTS not enforced check", () => {
  it("flags missing HSTS header on HTTPS responses", async () => {
    const findings = await executeCheck({ tls: true });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Strict-Transport-Security header missing",
      severity: "medium",
    });
  });

  it("flags low max-age", async () => {
    const findings = await executeCheck({
      tls: true,
      header: ["max-age=1000"],
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Strict-Transport-Security max-age too low",
      severity: "low",
    });
  });

  it("flags missing includeSubDomains", async () => {
    const findings = await executeCheck({
      tls: true,
      header: ["max-age=63072000"],
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Strict-Transport-Security missing includeSubDomains",
      severity: "low",
    });
  });

  it("does not flag when HSTS is properly configured", async () => {
    const findings = await executeCheck({
      tls: true,
      header: ["max-age=63072000; includeSubDomains; preload"],
    });
    expect(findings).toHaveLength(0);
  });

  it("does not flag HTTP responses", async () => {
    const findings = await executeCheck({ tls: false });
    expect(findings).toHaveLength(0);
  });
});
