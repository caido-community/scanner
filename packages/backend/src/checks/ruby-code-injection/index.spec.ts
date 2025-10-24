import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import rubyInjectionCheck from "./index";

const runRubyCheck = async (body: string): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "req-ruby",
    host: "example.com",
    method: "GET",
    path: "/vulnerable",
    headers: { Host: ["example.com"] },
  });

  const response = createMockResponse({
    id: "res-ruby",
    code: 200,
    headers: { "content-type": ["text/plain"] },
    body,
  });

  const execution = await runCheck(rubyInjectionCheck, [{ request, response }]);
  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Ruby code injection check", () => {
  it("flags Ruby evaluation evidence", async () => {
    const findings = await runRubyCheck("puts eval(params[:cmd])");

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Potential Ruby code injection",
      severity: "high",
    });
  });

  it("flags Ruby stack traces", async () => {
    const findings = await runRubyCheck(
      "NoMethodError: undefined method `eval'\n\tfrom app.rb:10:in `<main>'",
    );

    expect(findings).toHaveLength(1);
  });

  it("ignores unrelated errors", async () => {
    const findings = await runRubyCheck("TypeError: something else");
    expect(findings).toHaveLength(0);
  });
});
