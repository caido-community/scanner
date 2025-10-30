import {
  createMockRequest,
  createMockResponse,
  runCheck,
  type SendHandler,
} from "engine";
import { describe, expect, it } from "vitest";

import userAgentCheck from "./index";

type HandlerConfig = {
  statusDifference?: boolean;
  bodyDelta?: number;
  mobileBodyUndefined?: boolean;
};

const buildSendHandler = (config: HandlerConfig = {}): SendHandler => {
  return (spec) => {
    const userAgentHeader = spec.getHeader("User-Agent");
    const userAgent = userAgentHeader?.[0] ?? "";

    const isMobile = userAgent.toLowerCase().includes("mobile");

    let body: string | undefined = "identical response";
    if (config.bodyDelta !== undefined && isMobile === true) {
      body = `${body}${"x".repeat(config.bodyDelta)}`;
    }
    if (config.mobileBodyUndefined === true && isMobile === true) {
      body = undefined;
    }

    const mockRequest = createMockRequest({
      id: `sent-${userAgent}`,
      host: spec.getHost(),
      method: spec.getMethod(),
      path: spec.getPath(),
      headers: spec.getHeaders(),
    });

    const shouldRedirect =
      config.statusDifference === true && isMobile === true;
    const mockResponse = createMockResponse({
      id: `resp-${userAgent}`,
      code: shouldRedirect ? 302 : 200,
      headers: { "content-type": ["text/html"] },
      body,
    });

    return Promise.resolve({ request: mockRequest, response: mockResponse });
  };
};

describe("User agent dependent response check", () => {
  it("does not flag when responses are identical", async () => {
    const request = createMockRequest({
      id: "req-1",
      host: "example.com",
      method: "GET",
      path: "/",
      headers: { "User-Agent": ["Original UA"] },
    });

    const response = createMockResponse({
      id: "res-1",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "identical response",
    });

    const executionHistory = await runCheck(
      userAgentCheck,
      [{ request, response }],
      { sendHandler: buildSendHandler() },
    );

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(0);
  });

  it("flags differing responses", async () => {
    const request = createMockRequest({
      id: "req-2",
      host: "example.com",
      method: "GET",
      path: "/",
      headers: { "User-Agent": ["Original UA"] },
    });

    const response = createMockResponse({
      id: "res-2",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "identical response",
    });

    const executionHistory = await runCheck(
      userAgentCheck,
      [{ request, response }],
      { sendHandler: buildSendHandler({ statusDifference: true }) },
    );

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("medium");
  });

  it("does not flag when body length difference is within tolerance", async () => {
    const request = createMockRequest({
      id: "req-3",
      host: "example.com",
      method: "GET",
      path: "/",
      headers: { "User-Agent": ["Original UA"] },
    });

    const response = createMockResponse({
      id: "res-3",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "identical response",
    });

    const executionHistory = await runCheck(
      userAgentCheck,
      [{ request, response }],
      { sendHandler: buildSendHandler({ bodyDelta: 100 }) },
    );

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(0);
  });

  it("flags when body length difference exceeds tolerance", async () => {
    const request = createMockRequest({
      id: "req-4",
      host: "example.com",
      method: "GET",
      path: "/",
      headers: { "User-Agent": ["Original UA"] },
    });

    const response = createMockResponse({
      id: "res-4",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "identical response",
    });

    const executionHistory = await runCheck(
      userAgentCheck,
      [{ request, response }],
      { sendHandler: buildSendHandler({ bodyDelta: 101 }) },
    );

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(1);
  });

  it("handles responses that omit the body", async () => {
    const request = createMockRequest({
      id: "req-5",
      host: "example.com",
      method: "GET",
      path: "/",
      headers: { "User-Agent": ["Original UA"] },
    });

    const response = createMockResponse({
      id: "res-5",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "identical response",
    });

    const executionHistory = await runCheck(
      userAgentCheck,
      [{ request, response }],
      { sendHandler: buildSendHandler({ mobileBodyUndefined: true }) },
    );

    const findings =
      executionHistory[0]?.steps[executionHistory[0].steps.length - 1]
        ?.findings ?? [];
    expect(findings).toHaveLength(0);
  });
});
