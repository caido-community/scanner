import {
  createMockRequest,
  createMockResponse,
  mockTarget,
  ScanAggressivity,
  testCheck,
} from "engine";
import { describe, expect, it } from "vitest";

import inputReflectedCheck from "./index";

const firstHeaderValue = (
  headers: Record<string, string[]>,
  name: string,
): string | undefined => {
  for (const [key, values] of Object.entries(headers)) {
    if (key.toLowerCase() === name.toLowerCase()) {
      return values[0];
    }
  }

  return undefined;
};

describe("input-reflected check", () => {
  it("should detect reflected input in a query parameter", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/search",
        query: "q=test",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "safe",
      },
    });

    let callCount = 0;
    const { findings } = await testCheck(inputReflectedCheck, target, {
      sendHandler: (spec) => {
        callCount += 1;

        const q = new URLSearchParams(spec.getQuery()).get("q") ?? "";
        const body = q.includes("scanner-") ? `echo:${q}` : "safe";

        const request = createMockRequest({
          id: String(callCount + 1),
          host: spec.getHost(),
          method: spec.getMethod(),
          path: spec.getPath(),
          query: spec.getQuery(),
          headers: spec.getHeaders(),
        });

        const response = createMockResponse({
          id: String(callCount + 1),
          code: 200,
          headers: {},
          body,
        });

        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "info",
    });
    expect(callCount).toBe(1);
  });

  it("should detect reflected input in a cookie value", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/",
        headers: {
          cookie: ["theme=light; session=abc123"],
        },
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "safe",
      },
    });

    let callCount = 0;
    const { findings } = await testCheck(inputReflectedCheck, target, {
      sendHandler: (spec) => {
        callCount += 1;

        const cookie = firstHeaderValue(spec.getHeaders(), "cookie") ?? "";
        const body = cookie.includes("scanner-") ? cookie : "safe";

        const request = createMockRequest({
          id: String(callCount + 1),
          host: spec.getHost(),
          method: spec.getMethod(),
          path: spec.getPath(),
          query: spec.getQuery(),
          headers: spec.getHeaders(),
        });

        const response = createMockResponse({
          id: String(callCount + 1),
          code: 200,
          headers: {},
          body,
        });

        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "info",
    });
    expect(callCount).toBe(1);
  });

  it("should detect reflected input in a header value", async () => {
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
        body: "safe",
      },
    });

    let callCount = 0;
    const { findings } = await testCheck(inputReflectedCheck, target, {
      sendHandler: (spec) => {
        callCount += 1;

        const userAgent =
          firstHeaderValue(spec.getHeaders(), "user-agent") ?? "";
        const body = userAgent.includes("scanner-") ? userAgent : "safe";

        const request = createMockRequest({
          id: String(callCount + 1),
          host: spec.getHost(),
          method: spec.getMethod(),
          path: spec.getPath(),
          query: spec.getQuery(),
          headers: spec.getHeaders(),
        });

        const response = createMockResponse({
          id: String(callCount + 1),
          code: 200,
          headers: {},
          body,
        });

        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "info",
    });
    expect(callCount).toBe(1);
  });

  it("should find no issues when no injected marker is reflected", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/search",
        query: "a=1&b=2&c=3",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "safe",
      },
    });

    let callCount = 0;
    const { findings } = await testCheck(inputReflectedCheck, target, {
      sendHandler: (spec) => {
        callCount += 1;

        const request = createMockRequest({
          id: String(callCount + 1),
          host: spec.getHost(),
          method: spec.getMethod(),
          path: spec.getPath(),
          query: spec.getQuery(),
          headers: spec.getHeaders(),
        });

        const response = createMockResponse({
          id: String(callCount + 1),
          code: 200,
          headers: {},
          body: "safe",
        });

        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(0);
    expect(callCount).toBeGreaterThan(0);
  });

  it("should not run on non-GET requests", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/submit",
        query: "q=test",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "safe",
      },
    });

    let sendCallCount = 0;
    const { findings } = await testCheck(inputReflectedCheck, target, {
      sendHandler: () => {
        sendCallCount += 1;
        const request = createMockRequest({
          id: "2",
          host: "example.com",
          method: "POST",
          path: "/submit",
        });
        const response = createMockResponse({
          id: "2",
          code: 200,
          headers: {},
          body: "safe",
        });
        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(0);
    expect(sendCallCount).toBe(0);
  });

  it("should limit query vectors on LOW aggressivity", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/search",
        query: "a=1&b=2&c=3&d=4&e=5",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "safe",
      },
    });

    let callCount = 0;
    const { findings } = await testCheck(inputReflectedCheck, target, {
      sendHandler: (spec) => {
        callCount += 1;

        const query = spec.getQuery();
        const body = query.includes("d=scanner-") ? query : "safe";

        const request = createMockRequest({
          id: String(callCount + 1),
          host: spec.getHost(),
          method: spec.getMethod(),
          path: spec.getPath(),
          query,
          headers: spec.getHeaders(),
        });

        const response = createMockResponse({
          id: String(callCount + 1),
          code: 200,
          headers: {},
          body,
        });

        return Promise.resolve({ request, response });
      },
      config: { aggressivity: ScanAggressivity.LOW },
    });

    expect(findings).toHaveLength(0);
    expect(callCount).toBe(4);
  });
});
