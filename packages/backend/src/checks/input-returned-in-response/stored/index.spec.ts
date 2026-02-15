import {
  createMockRequest,
  createMockResponse,
  mockTarget,
  ScanAggressivity,
  testCheck,
} from "engine";
import { describe, expect, it } from "vitest";

import inputStoredCheck from "./index";

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

describe("input-stored check", () => {
  it("should detect stored input via a query parameter", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/profile",
        query: "name=alice",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "safe",
      },
    });

    let storedMarker: string | undefined;
    let callCount = 0;

    const { findings } = await testCheck(inputStoredCheck, target, {
      sendHandler: (spec) => {
        callCount += 1;

        const nameValue =
          new URLSearchParams(spec.getQuery()).get("name") ?? "";
        if (nameValue.includes("scanner-")) {
          storedMarker = nameValue;
        }

        const body =
          nameValue === "alice" && storedMarker !== undefined
            ? `stored:${storedMarker}`
            : "safe";

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
    expect(callCount).toBe(2);
  });

  it("should detect stored input via a cookie value", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/",
        headers: {
          cookie: ["theme=light"],
        },
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "safe",
      },
    });

    let storedMarker: string | undefined;
    let callCount = 0;

    const { findings } = await testCheck(inputStoredCheck, target, {
      sendHandler: (spec) => {
        callCount += 1;

        const cookie = firstHeaderValue(spec.getHeaders(), "cookie") ?? "";
        const match = cookie.match(/scanner-[a-z0-9]{8}/);
        if (match?.[0] !== undefined) {
          storedMarker = match[0];
        }

        const body =
          cookie.includes("theme=light") && storedMarker !== undefined
            ? `stored:${storedMarker}`
            : "safe";

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
    expect(callCount).toBe(2);
  });

  it("should find no issues when marker is not reflected in the follow-up response", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/profile",
        query: "name=alice",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "safe",
      },
    });

    let callCount = 0;
    const { findings } = await testCheck(inputStoredCheck, target, {
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
    const { findings } = await testCheck(inputStoredCheck, target, {
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
        query: "a=1&b=2&c=3&d=4",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "safe",
      },
    });

    let storedMarker: string | undefined;
    let callCount = 0;

    const { findings } = await testCheck(inputStoredCheck, target, {
      sendHandler: (spec) => {
        callCount += 1;

        const query = spec.getQuery();
        const match = query.match(/d=scanner-[a-z0-9]{8}/);
        if (match?.[0] !== undefined) {
          storedMarker = match[0].split("d=")[1];
        }

        const body =
          query === "a=1&b=2&c=3&d=4" && storedMarker !== undefined
            ? `stored:${storedMarker}`
            : "safe";

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
    expect(callCount).toBe(6);
  });
});
