import { type RequestSpec } from "caido:utils";
import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import ssjsCheck from "./index";

const buildSendHandler = (options?: { vulnerable?: boolean }) => {
  return (spec: RequestSpec) => {
    const query = spec.getQuery();
    const params = new URLSearchParams(query);
    let marker: string | undefined;

    for (const value of params.values()) {
      const decoded = decodeURIComponent(value);
      const match = decoded.match(/__ssjs_probe__[a-z0-9]+/i);
      if (match) {
        marker = match[0];
        break;
      }
    }

    const request = createMockRequest({
      id: "sent-request",
      host: spec.getHost(),
      method: spec.getMethod(),
      path: spec.getPath(),
      query: spec.getQuery(),
    });

    const isVulnerable = options?.vulnerable === true;
    const hasMarker = marker !== undefined;
    const body =
      isVulnerable && hasMarker
        ? `ReferenceError: ${marker} is not defined`
        : "Safe response";

    const response = createMockResponse({
      id: "sent-response",
      code: isVulnerable && hasMarker ? 500 : 200,
      headers: { "content-type": ["text/html"] },
      body,
    });

    return Promise.resolve({ request, response });
  };
};

describe("server-side JavaScript code injection check", () => {
  it("does nothing when no parameters are present", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "OK",
    });

    const executionHistory = await runCheck(ssjsCheck, [{ request, response }]);

    expect(executionHistory).toEqual([]);
  });

  it("does not raise findings when payloads do not execute", async () => {
    const request = createMockRequest({
      id: "2",
      host: "example.com",
      method: "GET",
      path: "/search",
      query: "q=test",
    });

    const response = createMockResponse({
      id: "2",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "Search results",
    });

    const executionHistory = await runCheck(
      ssjsCheck,
      [{ request, response }],
      { sendHandler: buildSendHandler({ vulnerable: false }) },
    );

    expect(executionHistory).toHaveLength(1);
    const lastStep =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1];
    expect(lastStep).toMatchObject({
      stepName: "testPayloads",
      findings: [],
      result: "done",
    });
  });

  it("detects when injected JavaScript throws controlled error", async () => {
    const request = createMockRequest({
      id: "3",
      host: "example.com",
      method: "GET",
      path: "/search",
      query: "q=test",
    });

    const response = createMockResponse({
      id: "3",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "Search results",
    });

    const executionHistory = await runCheck(
      ssjsCheck,
      [{ request, response }],
      { sendHandler: buildSendHandler({ vulnerable: true }) },
    );

    expect(executionHistory).toHaveLength(1);
    const checkRun = executionHistory[0];
    expect(checkRun).toMatchObject({
      checkId: "server-side-js-code-injection",
      targetRequestId: "3",
      status: "completed",
    });

    const lastStep = checkRun.steps[checkRun.steps.length - 1];
    expect(lastStep).toMatchObject({
      stepName: "testPayloads",
      result: "done",
    });

    const finding = lastStep.findings?.[0];
    expect(finding).toMatchObject({
      name: expect.stringContaining("Server-side JavaScript code injection"),
      severity: "critical",
    });
    expect(finding?.description).toContain("marker");
  });
});
