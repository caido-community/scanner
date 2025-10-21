import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import unrecognizedCharsetCheck from "./index";

describe("HTML uses unrecognized charset check", () => {
  it("finds unsupported charset in Content-Type header", async () => {
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
        "content-type": ["text/html; charset=foo-unknown"],
      },
      body: "<html><body>Hello</body></html>",
    });

    const executionHistory = await runCheck(unrecognizedCharsetCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(1);
    expect(findings[0]?.name).toBe("HTML uses unrecognized charset");
  });

  it("finds unsupported charset declared via meta tag", async () => {
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
        "content-type": ["text/html"],
      },
      body: `<html><head><meta charset="foo-unknown"></head><body>Hi</body></html>`,
    });

    const executionHistory = await runCheck(unrecognizedCharsetCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(1);
    expect(findings[0]?.description).toContain("meta tag");
  });

  it("does not alert for standard charset", async () => {
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
        "content-type": ["text/html; charset=UTF-8"],
      },
      body: `<html><head><meta charset="utf-8"></head><body>Hi</body></html>`,
    });

    const executionHistory = await runCheck(unrecognizedCharsetCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(0);
  });
});
