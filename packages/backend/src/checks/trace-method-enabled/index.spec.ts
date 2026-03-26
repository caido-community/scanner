import {
  createMockRequest,
  createMockResponse,
  mockTarget,
  testCheck,
} from "engine";
import { describe, expect, it } from "vitest";

import traceMethodCheck from "./index";

describe("trace-method-enabled check", () => {
  it("should detect TRACE method when canary is echoed back", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/test",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    const sendHandler = (spec: {
      getHeader: (name: string) => string[] | undefined;
    }) => {
      const traceHeader = spec.getHeader("X-Scanner-Trace")?.[0] ?? "";

      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "TRACE",
        path: "/test",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {},
        body: `TRACE /test HTTP/1.1\r\nHost: example.com\r\nX-Scanner-Trace: ${traceHeader}\r\n`,
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const { findings } = await testCheck(traceMethodCheck, target, {
      sendHandler,
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "TRACE Method Enabled",
      severity: "medium",
    });
  });

  it("should not detect when TRACE returns non-200", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/test",
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
        method: "TRACE",
        path: "/test",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 405,
        headers: {},
        body: "Method Not Allowed",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const { findings } = await testCheck(traceMethodCheck, target, {
      sendHandler,
    });

    expect(findings).toHaveLength(0);
  });

  it("should not detect when canary is not in response body", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/test",
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
        method: "TRACE",
        path: "/test",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {},
        body: "Some generic response without the canary",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const { findings } = await testCheck(traceMethodCheck, target, {
      sendHandler,
    });

    expect(findings).toHaveLength(0);
  });
});
