import {
  createMockRequest,
  createMockResponse,
  runCheck,
  type SendHandler,
} from "engine";
import { describe, expect, it } from "vitest";

import refererCheck from "./index";

type HandlerConfig = {
  statusDifference?: boolean;
  bodyDelta?: number;
};

const buildSendHandler = (config: HandlerConfig = {}): SendHandler => {
  return (spec) => {
    const refererHeader = spec.getHeader("Referer");
    const refererValue = refererHeader?.[0] ?? "";

    const isExternal = refererValue.includes("attacker.example");
    const status = config.statusDifference === true && isExternal ? 403 : 200;

    let body = "consistent content";
    if (config.bodyDelta !== undefined && isExternal) {
      body = `consistent content${"x".repeat(config.bodyDelta)}`;
    }

    const mockRequest = createMockRequest({
      id: `req-${refererValue}`,
      host: spec.getHost(),
      method: spec.getMethod(),
      path: spec.getPath(),
      headers: spec.getHeaders(),
    });

    const mockResponse = createMockResponse({
      id: `res-${refererValue}`,
      code: status,
      headers: { "content-type": ["text/html"] },
      body,
    });

    return Promise.resolve({ request: mockRequest, response: mockResponse });
  };
};

const runRefererCheck = async (
  handlerConfig?: HandlerConfig,
): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "target-req",
    host: "example.com",
    method: "GET",
    path: "/",
    headers: { Host: ["example.com"] },
  });

  const response = createMockResponse({
    id: "target-res",
    code: 200,
    headers: { "content-type": ["text/html"] },
    body: "baseline content",
  });

  const execution = await runCheck(refererCheck, [{ request, response }], {
    sendHandler: buildSendHandler(handlerConfig),
  });

  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Referer dependent response check", () => {
  it("reports when status codes differ for external referer", async () => {
    const findings = await runRefererCheck({ statusDifference: true });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Referer dependent response detected",
      severity: "medium",
    });
  });

  it("reports when body length differs significantly", async () => {
    const findings = await runRefererCheck({ bodyDelta: 150 });
    expect(findings).toHaveLength(1);
  });

  it("does not report when responses are identical", async () => {
    const findings = await runRefererCheck();
    expect(findings).toHaveLength(0);
  });

  it("does not report when body length difference is within tolerance", async () => {
    const findings = await runRefererCheck({ bodyDelta: 80 });
    expect(findings).toHaveLength(0);
  });
});
