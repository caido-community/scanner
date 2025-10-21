import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import aspNetDebugCheck from "./index";

describe("ASP.NET debugging check", () => {
  it("detects debug true marker", async () => {
    const request = createMockRequest({
      id: "req-1",
      host: "example.com",
      method: "GET",
      path: "/web.config",
    });

    const response = createMockResponse({
      id: "res-1",
      code: 200,
      headers: { "content-type": ["text/xml"] },
      body: '<configuration><system.web><compilation debug="true" /></system.web></configuration>',
    });

    const executionHistory = await runCheck(aspNetDebugCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(1);
    expect(findings[0]?.name).toBe("ASP.NET debugging enabled");
  });

  it("ignores responses without marker", async () => {
    const request = createMockRequest({
      id: "req-2",
      host: "example.com",
      method: "GET",
      path: "/web.config",
    });

    const response = createMockResponse({
      id: "res-2",
      code: 200,
      headers: { "content-type": ["text/xml"] },
      body: '<configuration><system.web><compilation debug="false" /></system.web></configuration>',
    });

    const executionHistory = await runCheck(aspNetDebugCheck, [
      { request, response },
    ]);

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(0);
  });
});
