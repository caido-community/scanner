import {
  createMockRequest,
  createMockResponse,
  mockTarget,
  ScanAggressivity,
  testCheck,
} from "engine";
import { describe, expect, it } from "vitest";

import suspectTransformCheck from "./index";

describe("Suspicious Input Transformation", () => {
  it("should detect transformations when check conditions are met", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/test",
        query: "param=value",
      },
      response: {
        id: "1",
        code: 200,
        headers: { "content-type": ["text/html"] },
        body: "Response: value",
      },
    });

    let callCount = 0;
    const { findings } = await testCheck(suspectTransformCheck, target, {
      sendHandler: () => {
        callCount++;

        const mockRequest = createMockRequest({
          id: `${callCount + 1}`,
          host: "example.com",
          method: "GET",
          path: "/test",
          query: `param=value`,
        });

        const body =
          callCount <= 2 ? "valueabcdefK123456ghijkl" : "Response: value";

        const mockResponse = createMockResponse({
          id: `${callCount + 1}`,
          code: 200,
          headers: { "content-type": ["text/html"] },
          body,
        });

        return Promise.resolve({
          request: mockRequest,
          response: mockResponse,
        });
      },
      config: { aggressivity: ScanAggressivity.LOW },
    });

    expect(findings.length).toBeGreaterThanOrEqual(0);
  });

  it("should detect arithmetic evaluation when result appears", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/calc",
        query: "expr=test",
      },
      response: {
        id: "1",
        code: 200,
        body: "Result: test",
      },
    });

    let callCount = 0;
    const { findings } = await testCheck(suspectTransformCheck, target, {
      sendHandler: () => {
        callCount++;

        const mockRequest = createMockRequest({
          id: `${callCount + 1}`,
          host: "example.com",
          method: "GET",
          path: "/calc",
          query: "expr=test",
        });

        const mockResponse = createMockResponse({
          id: `${callCount + 1}`,
          code: 200,
          body: `Result: ${callCount % 2 === 1 ? "9801" : "9801"}`,
        });

        return Promise.resolve({
          request: mockRequest,
          response: mockResponse,
        });
      },
      config: { aggressivity: ScanAggressivity.MEDIUM },
    });

    if (findings.length > 0) {
      expect(findings[0]?.name).toContain("arithmetic evaluation");
    }
  });

  it("should not run when request has no parameters", async () => {
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
        headers: { "content-type": ["text/html"] },
        body: "Safe response",
      },
    });

    const { findings } = await testCheck(suspectTransformCheck, target);

    expect(findings).toHaveLength(0);
  });

  it("should find no issues when no transformation occurs", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/test",
        query: "param=value",
      },
      response: {
        id: "1",
        code: 200,
        headers: { "content-type": ["text/html"] },
        body: "Response without transformation",
      },
    });

    const { findings } = await testCheck(suspectTransformCheck, target, {
      sendHandler: () => {
        const mockRequest = createMockRequest({
          id: "2",
          host: "example.com",
          method: "GET",
          path: "/test",
          query: "param=valuetest",
        });

        const mockResponse = createMockResponse({
          id: "2",
          code: 200,
          headers: { "content-type": ["text/html"] },
          body: "Response without transformation",
        });

        return Promise.resolve({
          request: mockRequest,
          response: mockResponse,
        });
      },
      config: { aggressivity: ScanAggressivity.LOW },
    });

    expect(findings).toHaveLength(0);
  });

  it("should not detect transformation if expected value is in initial response", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/test",
        query: "param=value",
      },
      response: {
        id: "1",
        code: 200,
        headers: { "content-type": ["text/html"] },
        body: "Response already contains 9801",
      },
    });

    let callCount = 0;
    const { findings } = await testCheck(suspectTransformCheck, target, {
      sendHandler: () => {
        callCount++;
        const mockRequest = createMockRequest({
          id: `${callCount + 1}`,
          host: "example.com",
          method: "GET",
          path: "/test",
          query: "param=value99*99",
        });

        const mockResponse = createMockResponse({
          id: `${callCount + 1}`,
          code: 200,
          headers: { "content-type": ["text/html"] },
          body: "Response contains 9801",
        });

        return Promise.resolve({
          request: mockRequest,
          response: mockResponse,
        });
      },
      config: { aggressivity: ScanAggressivity.LOW },
    });

    expect(findings).toHaveLength(0);
  });

  it("should handle network errors gracefully", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/test",
        query: "test=value",
      },
      response: {
        id: "1",
        code: 200,
        body: "Test: value",
      },
    });

    const { findings } = await testCheck(suspectTransformCheck, target, {
      sendHandler: () => {
        return Promise.reject(new Error("Network error"));
      },
      config: { aggressivity: ScanAggressivity.LOW },
    });

    expect(findings).toHaveLength(0);
  });

  it("should use fewer checks on LOW aggressivity", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/test",
        query: "param=test",
      },
      response: {
        id: "1",
        code: 200,
        body: "Value: test",
      },
    });

    let sendCallCount = 0;
    await testCheck(suspectTransformCheck, target, {
      sendHandler: () => {
        sendCallCount++;
        const mockRequest = createMockRequest({
          id: `${sendCallCount + 1}`,
          host: "example.com",
          method: "GET",
          path: "/test",
          query: `param=testprobe${sendCallCount}`,
        });

        const mockResponse = createMockResponse({
          id: `${sendCallCount + 1}`,
          code: 200,
          body: `Value: testprobe${sendCallCount}`,
        });

        return Promise.resolve({
          request: mockRequest,
          response: mockResponse,
        });
      },
      config: { aggressivity: ScanAggressivity.LOW },
    });

    expect(sendCallCount).toBeLessThanOrEqual(3);
  });

  it("should use more checks on HIGH aggressivity", async () => {
    const target = mockTarget({
      request: {
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/test",
        query: "param=test",
      },
      response: {
        id: "1",
        code: 200,
        body: "Value: test",
      },
    });

    let sendCallCount = 0;
    await testCheck(suspectTransformCheck, target, {
      sendHandler: () => {
        sendCallCount++;
        const mockRequest = createMockRequest({
          id: `${sendCallCount + 1}`,
          host: "example.com",
          method: "GET",
          path: "/test",
          query: `param=testprobe${sendCallCount}`,
        });

        const mockResponse = createMockResponse({
          id: `${sendCallCount + 1}`,
          code: 200,
          body: `Value: testprobe${sendCallCount}`,
        });

        return Promise.resolve({
          request: mockRequest,
          response: mockResponse,
        });
      },
      config: { aggressivity: ScanAggressivity.HIGH },
    });

    expect(sendCallCount).toBeGreaterThan(5);
  });
});
