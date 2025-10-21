import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import xssFilterDisabledCheck from "./index";

describe("X-XSS-Protection disabled check", () => {
  it("flags header disabling filter", async () => {
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
        "x-xss-protection": ["0"],
      },
      body: "OK",
    });

    const executionHistory = await runCheck(xssFilterDisabledCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(1);
    expect(findings[0]?.name).toBe("Browser XSS filter disabled");
  });

  it("ignores safe header values", async () => {
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
        "x-xss-protection": ["1; mode=block"],
      },
      body: "OK",
    });

    const executionHistory = await runCheck(xssFilterDisabledCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(0);
  });
});
