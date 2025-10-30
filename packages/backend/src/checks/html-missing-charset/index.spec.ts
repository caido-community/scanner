import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import htmlMissingCharsetCheck from "./index";

describe("HTML missing charset check", () => {
  it("flags HTML response without charset", async () => {
    const request = createMockRequest({
      id: "req-1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "res-1",
      code: 200,
      headers: {
        "content-type": ["text/html"],
      },
      body: "<html><head><title>Test</title></head><body>Hello</body></html>",
    });

    const executionHistory = await runCheck(htmlMissingCharsetCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(1);
    expect(findings[0]?.name).toBe("HTML does not specify charset");
  });

  it("does not flag when Content-Type contains charset", async () => {
    const request = createMockRequest({
      id: "req-2",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "res-2",
      code: 200,
      headers: {
        "content-type": ["text/html; charset=UTF-8"],
      },
      body: "<html><head><title>Safe</title></head><body>OK</body></html>",
    });

    const executionHistory = await runCheck(htmlMissingCharsetCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(0);
  });

  it("does not flag when meta charset is present", async () => {
    const request = createMockRequest({
      id: "req-3",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "res-3",
      code: 200,
      headers: {
        "content-type": ["text/html"],
      },
      body: `<html><head><meta charset="utf-8"></head><body>OK</body></html>`,
    });

    const executionHistory = await runCheck(htmlMissingCharsetCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(0);
  });
});
