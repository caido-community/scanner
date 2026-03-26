import {
  createMockRequest,
  createMockResponse,
  mockTarget,
  ScanAggressivity,
  testCheck,
} from "engine";
import { describe, expect, it } from "vitest";

import xmlInputDetectionCheck from "./index";

describe("xml-input-detection check", () => {
  it("should not run when method is GET", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/api/data",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    let sendCount = 0;
    const { findings } = await testCheck(xmlInputDetectionCheck, target, {
      sendHandler: () => {
        sendCount += 1;
        const mockRequest = createMockRequest({
          id: "2",
          host: "example.com",
          method: "POST",
          path: "/api/data",
        });
        const mockResponse = createMockResponse({
          id: "2",
          code: 200,
          headers: {},
          body: "OK",
        });
        return Promise.resolve({
          request: mockRequest,
          response: mockResponse,
        });
      },
      config: { aggressivity: ScanAggressivity.MEDIUM },
    });

    expect(findings).toHaveLength(0);
    expect(sendCount).toBe(0);
  });

  it("should detect when XML is parsed (different status codes)", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/api/data",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    let callCount = 0;
    const sendHandler = (spec: {
      getHeader: (name: string) => string[] | undefined;
    }) => {
      callCount += 1;
      const contentType = spec.getHeader("Content-Type")?.[0] ?? "";
      const isXml = contentType === "application/xml";

      const mockRequest = createMockRequest({
        id: String(callCount + 1),
        host: "example.com",
        method: "POST",
        path: "/api/data",
      });

      const mockResponse = createMockResponse({
        id: String(callCount + 1),
        code: isXml ? 200 : 415,
        headers: {},
        body: isXml ? "<response>ok</response>" : "Unsupported Media Type",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const { findings } = await testCheck(xmlInputDetectionCheck, target, {
      sendHandler,
      config: { aggressivity: ScanAggressivity.MEDIUM },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "XML Input Accepted",
      severity: "info",
    });
  });

  it("should not detect when both return same status code", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/api/data",
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
        method: "POST",
        path: "/api/data",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 415,
        headers: {},
        body: "Unsupported Media Type",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const { findings } = await testCheck(xmlInputDetectionCheck, target, {
      sendHandler,
      config: { aggressivity: ScanAggressivity.MEDIUM },
    });

    expect(findings).toHaveLength(0);
  });

  it("should not detect when XML response body is HTML", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/api/data",
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
        method: "POST",
        path: "/api/data",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {},
        body: "<html><body>Hello World</body></html>",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const { findings } = await testCheck(xmlInputDetectionCheck, target, {
      sendHandler,
      config: { aggressivity: ScanAggressivity.MEDIUM },
    });

    expect(findings).toHaveLength(0);
  });

  it("should run for PUT method", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "PUT",
        path: "/api/data",
      },
      response: {
        id: "1",
        code: 200,
        headers: {},
        body: "OK",
      },
    });

    let callCount = 0;
    const sendHandler = (spec: {
      getHeader: (name: string) => string[] | undefined;
    }) => {
      callCount += 1;
      const contentType = spec.getHeader("Content-Type")?.[0] ?? "";
      const isXml = contentType === "application/xml";

      const mockRequest = createMockRequest({
        id: String(callCount + 1),
        host: "example.com",
        method: "PUT",
        path: "/api/data",
      });

      const mockResponse = createMockResponse({
        id: String(callCount + 1),
        code: isXml ? 200 : 400,
        headers: {},
        body: isXml ? "<response>ok</response>" : "Bad Request",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const { findings } = await testCheck(xmlInputDetectionCheck, target, {
      sendHandler,
      config: { aggressivity: ScanAggressivity.MEDIUM },
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "XML Input Accepted",
      severity: "info",
    });
  });
});
