import {
  createMockRequest,
  createMockResponse,
  mockTarget,
  testCheck,
} from "engine";
import { describe, expect, it } from "vitest";

import userAgentCheck from "./index";

describe("user-agent-dependent-response check", () => {
  it("should not produce findings when probe responses match original response", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "test response",
      },
    });

    const { findings } = await testCheck(userAgentCheck, target, {
      sendHandler: (spec) => {
        const request = createMockRequest({
          id: "2",
          host: spec.getHost(),
          method: spec.getMethod(),
          path: spec.getPath(),
        });

        const response = createMockResponse({
          id: "2",
          code: 200,
          headers: {},
          body: "test response",
        });

        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(0);
  });

  it("should produce finding when user agents return different status codes", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "test response",
      },
    });

    const { findings } = await testCheck(userAgentCheck, target, {
      sendHandler: (spec) => {
        const userAgent = spec.getHeader("User-Agent")?.[0] ?? "";
        const isMobile = userAgent.toLowerCase().includes("mobile");

        const request = createMockRequest({
          id: "2",
          host: spec.getHost(),
          method: spec.getMethod(),
          path: spec.getPath(),
        });

        const response = createMockResponse({
          id: "2",
          code: isMobile ? 302 : 200,
          headers: {},
          body: "test response",
        });

        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "User agent dependent response detected",
      severity: "info",
    });
  });

  it("should produce finding when probe body length difference exceeds tolerance", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "test response",
      },
    });

    const { findings } = await testCheck(userAgentCheck, target, {
      sendHandler: (spec) => {
        const userAgent = spec.getHeader("User-Agent")?.[0] ?? "";
        const isMobile = userAgent.toLowerCase().includes("mobile");

        const request = createMockRequest({
          id: "2",
          host: spec.getHost(),
          method: spec.getMethod(),
          path: spec.getPath(),
        });

        const response = createMockResponse({
          id: "2",
          code: 200,
          headers: {},
          body: isMobile ? `test response${"x".repeat(101)}` : "test response",
        });

        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(1);
  });

  it("should not produce finding when probe body length difference is within tolerance", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "test response",
      },
    });

    const { findings } = await testCheck(userAgentCheck, target, {
      sendHandler: (spec) => {
        const userAgent = spec.getHeader("User-Agent")?.[0] ?? "";
        const isMobile = userAgent.toLowerCase().includes("mobile");

        const request = createMockRequest({
          id: "2",
          host: spec.getHost(),
          method: spec.getMethod(),
          path: spec.getPath(),
        });

        const response = createMockResponse({
          id: "2",
          code: 200,
          headers: {},
          body: isMobile ? `test response${"x".repeat(100)}` : "test response",
        });

        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(0);
  });

  it("should not produce finding when one probe omits body", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "test response",
      },
    });

    const { findings } = await testCheck(userAgentCheck, target, {
      sendHandler: (spec) => {
        const userAgent = spec.getHeader("User-Agent")?.[0] ?? "";
        const isMobile = userAgent.toLowerCase().includes("mobile");

        const request = createMockRequest({
          id: "2",
          host: spec.getHost(),
          method: spec.getMethod(),
          path: spec.getPath(),
        });

        const response = createMockResponse({
          id: "2",
          code: 200,
          headers: {},
          body: isMobile ? undefined : "test response",
        });

        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(0);
  });

  it("should not produce finding when all probes are identical but differ from original", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/",
      },
      response: {
        id: "1",
        code: 208,
        headers: {},
        body: undefined,
      },
    });

    const { findings } = await testCheck(userAgentCheck, target, {
      sendHandler: (spec) => {
        const request = createMockRequest({
          id: "2",
          host: spec.getHost(),
          method: spec.getMethod(),
          path: spec.getPath(),
        });

        const response = createMockResponse({
          id: "2",
          code: 401,
          headers: {},
          body: "x".repeat(102),
        });

        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(0);
  });

  it("should not run on non-GET requests", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "test response",
      },
    });

    let sendCallCount = 0;
    const { findings } = await testCheck(userAgentCheck, target, {
      sendHandler: (spec) => {
        sendCallCount += 1;
        const request = createMockRequest({
          id: "2",
          host: spec.getHost(),
          method: spec.getMethod(),
          path: spec.getPath(),
        });
        const response = createMockResponse({
          id: "2",
          code: 200,
          headers: {},
          body: "test response",
        });
        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(0);
    expect(sendCallCount).toBe(0);
  });
});
