import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import hostHeaderInjectionCheck from "./index";

describe("host-header-injection check", () => {
  it("should not run when hostname is not reflected in baseline response", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/test",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: {},
      body: "Hello World",
    });

    const executionHistory = await runCheck(hostHeaderInjectionCheck, [
      { request, response },
    ]);

    const findings = executionHistory.flatMap((e) =>
      e.steps.flatMap((s) => s.findings),
    );

    expect(findings.length).toBe(0);
  });

  it("should not detect when canary is not reflected in response", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/test",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: {},
      body: "Welcome to example.com",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/test",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {},
        body: "Welcome to example.com",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      hostHeaderInjectionCheck,
      [{ request, response }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    const findings = executionHistory.flatMap((e) =>
      e.steps.flatMap((s) => s.findings),
    );

    expect(findings.length).toBe(0);
  });

  it("should detect host header injection when canary is reflected", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/test",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: {},
      body: "Welcome to example.com",
    });

    const sendHandler = (spec: {
      getHeader: (name: string) => string[] | undefined;
    }) => {
      const hostHeader = spec.getHeader("Host")?.[0] ?? "";
      const xForwardedHost = spec.getHeader("X-Forwarded-Host")?.[0] ?? "";
      const injectedHost = xForwardedHost || hostHeader;

      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/test",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {},
        body: `Welcome to ${injectedHost}`,
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      hostHeaderInjectionCheck,
      [{ request, response }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    const findings = executionHistory.flatMap((e) =>
      e.steps.flatMap((s) => s.findings),
    );

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]).toMatchObject({
      name: expect.stringContaining("Host Value Reflected"),
    });
  });

  it("should not run when response has no body", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/test",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: {},
      body: "",
    });

    const executionHistory = await runCheck(hostHeaderInjectionCheck, [
      { request, response },
    ]);

    const findings = executionHistory.flatMap((e) =>
      e.steps.flatMap((s) => s.findings),
    );

    expect(findings.length).toBe(0);
  });

  it("should test more variants on higher aggressivity", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/test",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: {},
      body: "Welcome to example.com",
    });

    let sendCount = 0;
    const sendHandler = () => {
      sendCount += 1;
      const mockRequest = createMockRequest({
        id: String(sendCount + 1),
        host: "example.com",
        method: "GET",
        path: "/test",
      });

      const mockResponse = createMockResponse({
        id: String(sendCount + 1),
        code: 200,
        headers: {},
        body: "Welcome to example.com",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    await runCheck(hostHeaderInjectionCheck, [{ request, response }], {
      sendHandler,
      config: { aggressivity: ScanAggressivity.HIGH },
    });

    expect(sendCount).toBeGreaterThan(2);
  });
});
