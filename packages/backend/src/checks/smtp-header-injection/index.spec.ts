import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import smtpHeaderInjectionCheck from "./index";

const runCheckWith = async (config: {
  query?: string;
  body?: string;
}): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "req-smtp",
    host: "example.com",
    method: config.body !== undefined ? "POST" : "GET",
    path: "/mail",
    query: config.query,
    headers: {
      Host: ["example.com"],
      "Content-Type": ["application/x-www-form-urlencoded"],
    },
    body: config.body,
  });

  const response = createMockResponse({
    id: "res-smtp",
    code: 200,
    headers: { "content-type": ["text/html"] },
    body: "",
  });

  const execution = await runCheck(smtpHeaderInjectionCheck, [
    { request, response },
  ]);

  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("SMTP header injection detection", () => {
  it("flags newline injection in query string", async () => {
    const findings = await runCheckWith({
      query: "email=foo@example.com%0d%0aBcc:evil@example.com",
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "SMTP header injection indicators",
      severity: "medium",
    });
  });

  it("flags header prefixes in body", async () => {
    const findings = await runCheckWith({
      body: "message=To:admin@example.com",
    });

    expect(findings).toHaveLength(1);
  });

  it("ignores safe inputs", async () => {
    const findings = await runCheckWith({ query: "email=foo@example.com" });
    expect(findings).toHaveLength(0);
  });
});
