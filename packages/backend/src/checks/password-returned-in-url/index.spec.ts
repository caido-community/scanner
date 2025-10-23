import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import passwordUrlCheck from "./index";

const executeCheck = async (config: {
  body?: string;
  location?: string[];
}): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "req-password-url",
    host: "example.com",
    method: "GET",
    path: "/",
    headers: { Host: ["example.com"] },
  });

  const response = createMockResponse({
    id: "res-password-url",
    code: 200,
    headers: {
      "content-type": ["text/html"],
      ...(config.location !== undefined ? { location: config.location } : {}),
    },
    body: config.body ?? "",
  });

  const execution = await runCheck(passwordUrlCheck, [{ request, response }]);

  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Password returned in URL query string check", () => {
  it("flags password parameter in response body URL", async () => {
    const findings = await executeCheck({
      body: '<a href="https://example.com/reset?password=Secret123">link</a>',
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "high",
      name: "Password returned in URL query string",
    });
  });

  it("flags password parameter in Location header", async () => {
    const findings = await executeCheck({
      location: ["https://example.com/callback?pwd=%50%40ssw0rd"],
    });

    expect(findings).toHaveLength(1);
  });

  it("does not flag when no password indicators exist", async () => {
    const findings = await executeCheck({
      body: '<a href="https://example.com/reset?token=abc123">link</a>',
    });

    expect(findings).toHaveLength(0);
  });
});
