import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import requestUrlOverrideCheck from "./index";

const runOverrideCheck = async (
  headers: Record<string, string[]>,
): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "req-url-override",
    host: "example.com",
    method: "GET",
    path: "/",
    headers: { Host: ["example.com"] },
  });

  const response = createMockResponse({
    id: "res-url-override",
    code: 200,
    headers,
    body: "",
  });

  const execution = await runCheck(requestUrlOverrideCheck, [
    { request, response },
  ]);

  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Request URL override check", () => {
  it("flags X-Original-URL header", async () => {
    const findings = await runOverrideCheck({
      "x-original-url": ["/admin"],
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Request URL override header exposed",
      severity: "medium",
    });
  });

  it("flags X-Rewrite-URL header", async () => {
    const findings = await runOverrideCheck({
      "x-rewrite-url": ["/private"],
    });

    expect(findings).toHaveLength(1);
  });

  it("ignores responses without override headers", async () => {
    const findings = await runOverrideCheck({ "content-type": ["text/html"] });
    expect(findings).toHaveLength(0);
  });
});
