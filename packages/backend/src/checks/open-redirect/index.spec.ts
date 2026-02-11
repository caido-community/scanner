import {
  createMockRequest,
  createMockResponse,
  mockTarget,
  testCheck,
} from "engine";
import { describe, expect, it } from "vitest";

import openRedirectCheck, {
  getExpectedHostInfo,
  getSuspiciousParamsFromQuery,
} from "./index";

describe("open-redirect check", () => {
  it("should not run when no URL parameters are present", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    const { findings } = await testCheck(openRedirectCheck, target);

    expect(findings).toHaveLength(0);
  });

  it("should not run when no suspicious URL parameters are found", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "foo=bar&baz=qux",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    const { findings } = await testCheck(openRedirectCheck, target);

    expect(findings).toHaveLength(0);
  });

  it("should not produce finding when no redirect occurs", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "redirect=https://example.com/safe",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/page",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {},
        body: "OK",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const { findings } = await testCheck(openRedirectCheck, target, {
      sendHandler,
    });

    expect(findings).toHaveLength(0);
  });

  it("should detect open redirect vulnerability", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "redirect=https://example.com/safe",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/page",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 302,
        headers: {
          Location: ["https://scanner-attacker.invalid/"],
        },
        body: "",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const { findings } = await testCheck(openRedirectCheck, target, {
      sendHandler,
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Open Redirect in parameter 'redirect'",
      severity: "medium",
    });
    expect(findings[0]?.correlation?.requestID).toBe("2");
  });

  it("should not report finding when redirect stays on expected host", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "redirect=https://example.com/safe",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/page",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 302,
        headers: {
          Location: ["https://example.com/account"],
        },
        body: "",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const { findings } = await testCheck(openRedirectCheck, target, {
      sendHandler,
    });

    expect(findings).toHaveLength(0);
  });

  it("should test multiple parameters sequentially", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "redirect=safe&url=also-safe",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/page",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {},
        body: "OK",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const { findings } = await testCheck(openRedirectCheck, target, {
      sendHandler,
    });

    expect(findings).toHaveLength(0);
  });

  it("extracts suspicious URL parameters from names and values", () => {
    expect(getSuspiciousParamsFromQuery("foo=bar")).toEqual([]);
    expect(
      getSuspiciousParamsFromQuery("redirect=https://example.com"),
    ).toEqual(["redirect"]);
    expect(getSuspiciousParamsFromQuery("next=/home")).toEqual(["next"]);
  });

  it("derives expected host info from parameter URL or request info", () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      port: 8080,
      method: "GET",
      path: "/page",
    });

    expect(
      getExpectedHostInfo(request, "https://api.example.org/path"),
    ).toEqual({
      host: "api.example.org",
      protocol: "https:",
    });

    expect(getExpectedHostInfo(request, undefined)).toEqual({
      host: "example.com:8080",
      protocol: "https:",
    });
  });
});
