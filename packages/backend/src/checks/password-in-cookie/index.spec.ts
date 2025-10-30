import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import passwordCookieCheck from "./index";

const runPasswordCookieCheck = async (
  setCookieHeaders: string[],
): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "req-cookie",
    host: "example.com",
    method: "GET",
    path: "/",
    headers: { Host: ["example.com"] },
  });

  const response = createMockResponse({
    id: "res-cookie",
    code: 200,
    headers: { "set-cookie": setCookieHeaders },
    body: "",
  });

  const execution = await runCheck(passwordCookieCheck, [
    { request, response },
  ]);

  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Password value stored in cookie check", () => {
  it("flags cookies whose name indicates a password", async () => {
    const findings = await runPasswordCookieCheck([
      "password=SuperSecret123; Path=/; HttpOnly",
    ]);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Password value stored in cookie",
      severity: "high",
    });
  });

  it("flags cookies whose value indicates a password", async () => {
    const findings = await runPasswordCookieCheck([
      "auth=Pwd%3DPlainText; Path=/; HttpOnly",
    ]);

    expect(findings).toHaveLength(1);
  });

  it("does not flag unrelated cookies", async () => {
    const findings = await runPasswordCookieCheck([
      "sessionid=abcdef123456; Path=/; HttpOnly; Secure",
    ]);

    expect(findings).toHaveLength(0);
  });
});
