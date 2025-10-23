import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import sessionTokenCheck from "./index";

const buildTarget = (config: {
  body?: string;
  location?: string[];
}): {
  request: ReturnType<typeof createMockRequest>;
  response: ReturnType<typeof createMockResponse>;
} => {
  const request = createMockRequest({
    id: "req-session-token",
    host: "example.com",
    method: "GET",
    path: "/",
    headers: { Host: ["example.com"] },
  });

  const response = createMockResponse({
    id: "res-session-token",
    code: 200,
    headers: {
      "content-type": ["text/html"],
      ...(config.location !== undefined ? { location: config.location } : {}),
    },
    body: config.body ?? "",
  });

  return { request, response };
};

const executeCheck = async (config: {
  body?: string;
  location?: string[];
}): Promise<unknown[]> => {
  const target = buildTarget(config);
  const execution = await runCheck(sessionTokenCheck, [target]);
  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Session token in URL check", () => {
  it("flags session tokens in response body URLs", async () => {
    const findings = await executeCheck({
      body: '<a href="https://example.com/callback?sessionToken=abc123">return</a>',
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Session token disclosed in URL",
      severity: "high",
    });
  });

  it("flags session tokens in Location header", async () => {
    const findings = await executeCheck({
      location: ["https://example.com/callback?token=xyz"],
    });

    expect(findings).toHaveLength(1);
  });

  it("does not flag unrelated parameters", async () => {
    const findings = await executeCheck({
      body: '<a href="https://example.com/callback?state=123">return</a>',
    });

    expect(findings).toHaveLength(0);
  });
});
