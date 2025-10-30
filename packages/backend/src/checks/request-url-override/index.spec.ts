import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import requestUrlOverrideCheck from "./index";

const runOverrideCheck = async (
  requestHeaders: Record<string, string[]>,
  responseHeaders: Record<string, string[]>,
): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "req-url-override",
    host: "example.com",
    method: "GET",
    path: "/",
    headers: { Host: ["example.com"], ...requestHeaders },
  });

  const response = createMockResponse({
    id: "res-url-override",
    code: 200,
    headers: responseHeaders,
    body: "",
  });

  const execution = await runCheck(requestUrlOverrideCheck, [
    { request, response },
  ]);

  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Request URL override check", () => {
  it("flags X-Original-URL response header", async () => {
    const findings = await runOverrideCheck(
      {},
      {
        "x-original-url": ["/admin"],
      },
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Request URL override headers observed",
      severity: "medium",
    });
  });

  it("flags request override headers", async () => {
    const findings = await runOverrideCheck(
      { "x-forwarded-uri": ["/admin"] },
      {},
    );

    expect(findings).toHaveLength(1);
  });

  it("ignores responses without override headers", async () => {
    const findings = await runOverrideCheck(
      {},
      { "content-type": ["text/html"] },
    );
    expect(findings).toHaveLength(0);
  });
});
