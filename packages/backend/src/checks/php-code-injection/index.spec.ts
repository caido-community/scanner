import {
  createMockRequest,
  createMockResponse,
  mockTarget,
  ScanAggressivity,
  testCheck,
} from "engine";
import { describe, expect, it } from "vitest";

import phpCodeInjectionCheck from "./index";

const decodeMaybe = (value: string): string => {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
};

const extractMarker = (payload: string): string | undefined => {
  return payload.match(/scanner-phpci-([a-z0-9]+)-/)?.[1];
};

const expectedTokenForMarker = (marker: string): string => {
  return `scanner-phpci-${marker}-9801547`;
};

describe("php-code-injection check", () => {
  it("should detect PHP code injection when output token appears (direct probe)", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/calc",
        query: "code=test",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    let callCount = 0;
    const { findings } = await testCheck(phpCodeInjectionCheck, target, {
      sendHandler: (spec) => {
        callCount += 1;

        const params = new URLSearchParams(spec.getQuery());
        const payload = params.get("code") ?? "";
        const marker = extractMarker(payload);

        const request = createMockRequest({
          id: String(callCount + 1),
          host: spec.getHost(),
          method: spec.getMethod(),
          path: spec.getPath(),
          query: spec.getQuery(),
        });

        const responseBody =
          marker !== undefined ? expectedTokenForMarker(marker) : "safe";

        const response = createMockResponse({
          id: String(callCount + 1),
          code: 200,
          headers: {},
          body: responseBody,
        });

        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "PHP code injection in parameter 'code'",
      severity: "critical",
    });
  });

  it("should detect PHP code injection when breakout probe succeeds after direct probe fails", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/calc",
        query: "code=test",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    let callCount = 0;
    const { findings } = await testCheck(phpCodeInjectionCheck, target, {
      sendHandler: (spec) => {
        callCount += 1;

        const params = new URLSearchParams(spec.getQuery());
        const payload = params.get("code") ?? "";
        const marker = extractMarker(payload);

        const request = createMockRequest({
          id: String(callCount + 1),
          host: spec.getHost(),
          method: spec.getMethod(),
          path: spec.getPath(),
          query: spec.getQuery(),
        });

        const isDirectProbe = payload.startsWith("print('scanner-phpci-");
        const isSingleQuoteBreakout = payload.startsWith(
          "';print('scanner-phpci-",
        );

        const responseBody =
          !isDirectProbe && isSingleQuoteBreakout && marker !== undefined
            ? expectedTokenForMarker(marker)
            : decodeMaybe(payload);

        const response = createMockResponse({
          id: String(callCount + 1),
          code: 200,
          headers: {},
          body: responseBody,
        });

        return Promise.resolve({ request, response });
      },
      config: { aggressivity: ScanAggressivity.MEDIUM },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "PHP code injection in parameter 'code'",
      severity: "critical",
    });
  });

  it("should detect PHP code injection in POST body parameters", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/submit",
        headers: { "content-type": ["application/x-www-form-urlencoded"] },
        body: "code=test",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    let callCount = 0;
    const { findings } = await testCheck(phpCodeInjectionCheck, target, {
      sendHandler: (spec) => {
        callCount += 1;

        const bodyText = spec.getBody()?.toText() ?? "";
        const params = new URLSearchParams(bodyText);
        const payload = params.get("code") ?? "";
        const marker = extractMarker(payload);

        const request = createMockRequest({
          id: String(callCount + 1),
          host: spec.getHost(),
          method: spec.getMethod(),
          path: spec.getPath(),
          headers: spec.getHeaders(),
          body: bodyText,
        });

        const responseBody =
          marker !== undefined ? expectedTokenForMarker(marker) : "safe";

        const response = createMockResponse({
          id: String(callCount + 1),
          code: 200,
          headers: {},
          body: responseBody,
        });

        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "PHP code injection in parameter 'code'",
      severity: "critical",
    });
  });

  it("should find no issues when payload is reflected but not executed", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/calc",
        query: "code=test",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    let callCount = 0;
    const { findings } = await testCheck(phpCodeInjectionCheck, target, {
      sendHandler: (spec) => {
        callCount += 1;

        const params = new URLSearchParams(spec.getQuery());
        const payload = params.get("code") ?? "";

        const request = createMockRequest({
          id: String(callCount + 1),
          host: spec.getHost(),
          method: spec.getMethod(),
          path: spec.getPath(),
          query: spec.getQuery(),
        });

        const response = createMockResponse({
          id: String(callCount + 1),
          code: 200,
          headers: {},
          body: decodeMaybe(payload),
        });

        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(0);
  });

  it("should not run when request has no parameters", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/calc",
        query: "",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    let sendCallCount = 0;
    const { findings } = await testCheck(phpCodeInjectionCheck, target, {
      sendHandler: () => {
        sendCallCount += 1;
        const request = createMockRequest({
          id: "2",
          host: "example.com",
          method: "GET",
          path: "/calc",
        });
        const response = createMockResponse({
          id: "2",
          code: 200,
          headers: {},
          body: "OK",
        });
        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(0);
    expect(sendCallCount).toBe(0);
  });

  it("should not run when target has no response", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/calc",
        query: "code=test",
      },
      response: undefined,
    });

    let sendCallCount = 0;
    const { findings } = await testCheck(phpCodeInjectionCheck, target, {
      sendHandler: () => {
        sendCallCount += 1;
        const request = createMockRequest({
          id: "2",
          host: "example.com",
          method: "GET",
          path: "/calc",
        });
        const response = createMockResponse({
          id: "2",
          code: 200,
          headers: {},
          body: "OK",
        });
        return Promise.resolve({ request, response });
      },
    });

    expect(findings).toHaveLength(0);
    expect(sendCallCount).toBe(0);
  });

  it("should limit probes on LOW aggressivity", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/calc",
        query: "code=test",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    let sendCallCount = 0;
    const { findings } = await testCheck(phpCodeInjectionCheck, target, {
      sendHandler: (spec) => {
        sendCallCount += 1;

        const params = new URLSearchParams(spec.getQuery());
        const payload = params.get("code") ?? "";
        const marker = extractMarker(payload);

        const request = createMockRequest({
          id: String(sendCallCount + 1),
          host: spec.getHost(),
          method: spec.getMethod(),
          path: spec.getPath(),
          query: spec.getQuery(),
        });

        const isDoubleQuoteBreakout = payload.startsWith(
          "\";print('scanner-phpci-",
        );

        const responseBody =
          isDoubleQuoteBreakout && marker !== undefined
            ? expectedTokenForMarker(marker)
            : "safe";

        const response = createMockResponse({
          id: String(sendCallCount + 1),
          code: 200,
          headers: {},
          body: responseBody,
        });

        return Promise.resolve({ request, response });
      },
      config: { aggressivity: ScanAggressivity.LOW },
    });

    expect(findings).toHaveLength(0);
    expect(sendCallCount).toBe(2);
  });
});
