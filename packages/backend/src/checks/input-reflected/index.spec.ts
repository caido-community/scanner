import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import inputReflectedCheck from "./index";

const executeCheck = async (config: {
  requestQuery?: string;
  requestBody?: string;
  body: string;
}): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "req-input-reflected",
    host: "example.com",
    method: config.requestBody !== undefined ? "POST" : "GET",
    path: "/search",
    query: config.requestQuery ?? "",
    headers: { Host: ["example.com"], "Content-Type": ["application/json"] },
    body: config.requestBody,
  });

  const response = createMockResponse({
    id: "res-input-reflected",
    code: 200,
    headers: { "content-type": ["text/html"] },
    body: config.body,
  });

  const execution = await runCheck(inputReflectedCheck, [
    { request, response },
  ]);

  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Input reflected check", () => {
  it("flags reflected query parameters", async () => {
    const findings = await executeCheck({
      requestQuery: "q=test",
      body: "<p>Results for test</p>",
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Input reflected in response",
      severity: "low",
    });
  });

  it("flags reflected body parameters", async () => {
    const findings = await executeCheck({
      requestBody: JSON.stringify({ term: "abc" }),
      body: '<div data-term="abc"></div>',
    });

    expect(findings).toHaveLength(1);
  });

  it("ignores responses without reflections", async () => {
    const findings = await executeCheck({
      requestQuery: "q=test",
      body: "<p>No echo here</p>",
    });

    expect(findings).toHaveLength(0);
  });
});
