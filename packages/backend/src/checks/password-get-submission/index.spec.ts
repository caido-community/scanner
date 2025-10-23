import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import passwordGetCheck from "./index";

const buildTarget = (config: {
  method: string;
  path?: string;
  query?: string;
}): {
  request: ReturnType<typeof createMockRequest>;
  response: ReturnType<typeof createMockResponse>;
} => {
  const request = createMockRequest({
    id: `req-${config.method.toLowerCase()}`,
    host: "example.com",
    method: config.method,
    path: config.path ?? "/login",
    query: config.query,
    headers: { Host: ["example.com"] },
  });

  const response = createMockResponse({
    id: `res-${config.method.toLowerCase()}`,
    code: 200,
    headers: { "content-type": ["text/html"] },
    body: "<html></html>",
  });

  return { request, response };
};

const extractFindings = async (
  target: ReturnType<typeof buildTarget>,
): Promise<unknown[]> => {
  const execution = await runCheck(passwordGetCheck, [target]);
  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Password submitted using GET method check", () => {
  it("flags GET requests with password query parameter", async () => {
    const target = buildTarget({
      method: "GET",
      query: "username=user&password=secret123",
    });

    const findings = await extractFindings(target);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "high",
      name: "Password submitted using GET method",
    });
  });

  it("flags GET requests with derived password parameter names", async () => {
    const target = buildTarget({
      method: "GET",
      query: "userPassword=s3cr3t",
    });

    const findings = await extractFindings(target);
    expect(findings).toHaveLength(1);
  });

  it("does not flag when password-like parameters are absent", async () => {
    const target = buildTarget({
      method: "GET",
      query: "username=user&token=abc",
    });

    const findings = await extractFindings(target);
    expect(findings).toHaveLength(0);
  });

  it("does not flag non-GET requests", async () => {
    const target = buildTarget({
      method: "POST",
      query: "password=secret",
    });

    const findings = await extractFindings(target);
    expect(findings).toHaveLength(0);
  });
});
