import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import cacheableHttpsCheck from "./index";

describe("Cacheable HTTPS response check", () => {
  it("flags HTTPS response without cache directives", async () => {
    const request = createMockRequest({
      id: "req-1",
      host: "example.com",
      method: "GET",
      path: "/",
      tls: true,
    });

    const response = createMockResponse({
      id: "res-1",
      code: 200,
      headers: {
        "content-type": ["text/html"],
      },
      body: "OK",
    });

    const executionHistory = await runCheck(cacheableHttpsCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(1);
    expect(findings[0]?.name).toBe("Cacheable HTTPS response");
  });

  it("ignores responses with protective cache-control", async () => {
    const request = createMockRequest({
      id: "req-2",
      host: "example.com",
      method: "GET",
      path: "/",
      tls: true,
    });

    const response = createMockResponse({
      id: "res-2",
      code: 200,
      headers: {
        "cache-control": ["no-store, private"],
      },
      body: "OK",
    });

    const executionHistory = await runCheck(cacheableHttpsCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(0);
  });

  it("ignores HTTP responses", async () => {
    const request = createMockRequest({
      id: "req-3",
      host: "example.com",
      method: "GET",
      path: "/",
      tls: false,
    });

    const response = createMockResponse({
      id: "res-3",
      code: 200,
      headers: {},
      body: "OK",
    });

    const executionHistory = await runCheck(cacheableHttpsCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(0);
  });
});
