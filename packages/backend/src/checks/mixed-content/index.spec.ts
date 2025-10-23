import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import mixedContentCheck from "./index";

const buildTarget = (config: {
  tls: boolean;
  body: string;
}): {
  request: ReturnType<typeof createMockRequest>;
  response: ReturnType<typeof createMockResponse>;
} => {
  const request = createMockRequest({
    id: "req-mixed",
    host: "example.com",
    method: "GET",
    path: "/",
    tls: config.tls,
    headers: { Host: ["example.com"] },
  });

  const response = createMockResponse({
    id: "res-mixed",
    code: 200,
    headers: { "content-type": ["text/html"] },
    body: config.body,
  });

  return { request, response };
};

const runMixedContentCheck = async (
  tls: boolean,
  body: string,
): Promise<unknown[]> => {
  const target = buildTarget({ tls, body });
  const execution = await runCheck(mixedContentCheck, [target]);
  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Mixed content check", () => {
  it("flags http resources on HTTPS page", async () => {
    const findings = await runMixedContentCheck(
      true,
      '<img src="http://cdn.example.com/logo.png">',
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Mixed content detected",
      severity: "medium",
    });
  });

  it("flags CSS url references", async () => {
    const findings = await runMixedContentCheck(
      true,
      '<style>body { background: url("http://cdn.example.com/bg.png"); }</style>',
    );

    expect(findings).toHaveLength(1);
  });

  it("does not flag resources on HTTP pages", async () => {
    const findings = await runMixedContentCheck(
      false,
      '<script src="http://cdn.example.com/app.js"></script>',
    );

    expect(findings).toHaveLength(0);
  });

  it("does not flag HTTPS resources", async () => {
    const findings = await runMixedContentCheck(
      true,
      '<script src="https://cdn.example.com/app.js"></script>',
    );

    expect(findings).toHaveLength(0);
  });
});
