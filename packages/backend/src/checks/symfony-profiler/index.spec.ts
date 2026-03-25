import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import symfonyProfilerCheck from "./index";

describe("symfony-profiler check", () => {
  it("should detect exposed Symfony profiler with Symfony signature", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/page",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/app/_profiler/latest",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/html"],
        },
        body: '<html><body><div class="sf-toolbar">Symfony Profiler</div></body></html>',
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      symfonyProfilerCheck,
      [{ request, response: undefined }],
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
      name: "Symfony Profiler Exposed",
      severity: "high",
    });
  });

  it("should detect profiler with sf-toolbar signature", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/page",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/app/_profiler/latest",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/html"],
        },
        body: '<html><body><div id="sf-toolbar">Debug toolbar</div></body></html>',
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      symfonyProfilerCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    const findings = executionHistory.flatMap((e) =>
      e.steps.flatMap((s) => s.findings),
    );

    expect(findings.length).toBeGreaterThan(0);
  });

  it("should not detect when endpoint returns 404", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/page",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/app/_profiler/latest",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 404,
        headers: {},
        body: "Not Found",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      symfonyProfilerCheck,
      [{ request, response: undefined }],
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

  it("should not detect when response does not contain Symfony signatures", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/page",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/app/_profiler/latest",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/html"],
        },
        body: "<html><body>Welcome to the app</body></html>",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      symfonyProfilerCheck,
      [{ request, response: undefined }],
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

  it("should test both endpoints on medium aggressivity", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/page",
    });

    const testedPaths: string[] = [];
    const sendHandler = (spec: { getPath: () => string }) => {
      testedPaths.push(spec.getPath());

      const mockRequest = createMockRequest({
        id: String(testedPaths.length + 1),
        host: "example.com",
        method: "GET",
        path: spec.getPath(),
      });

      const mockResponse = createMockResponse({
        id: String(testedPaths.length + 1),
        code: 404,
        headers: {},
        body: "Not found",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    await runCheck(symfonyProfilerCheck, [{ request, response: undefined }], {
      sendHandler,
      config: { aggressivity: ScanAggressivity.MEDIUM },
    });

    const hasLatest = testedPaths.some((p) => p.includes("_profiler/latest"));
    const hasOpen = testedPaths.some((p) => p.includes("_profiler/open"));

    expect(hasLatest).toBe(true);
    expect(hasOpen).toBe(true);
  });
});
