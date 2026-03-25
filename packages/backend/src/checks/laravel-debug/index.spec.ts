import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import laravelDebugCheck from "./index";

describe("laravel-debug check", () => {
  it("should detect exposed Ignition health check endpoint", async () => {
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
        path: "/app/_ignition/health-check",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["application/json"],
        },
        body: JSON.stringify({ can_execute_commands: true }),
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      laravelDebugCheck,
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
      name: "Laravel Ignition Health Check",
      severity: "high",
    });
  });

  it("should detect exposed Clockwork endpoint on medium aggressivity", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/page",
    });

    const sendHandler = (spec: { getPath: () => string }) => {
      const path = spec.getPath();

      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path,
      });

      if (path.includes("__clockwork")) {
        const mockResponse = createMockResponse({
          id: "2",
          code: 200,
          headers: {
            "Content-Type": ["application/json"],
          },
          body: JSON.stringify({
            id: "123",
            method: "GET",
            uri: "/app/page",
            time: 1234567890,
          }),
        });
        return Promise.resolve({
          request: mockRequest,
          response: mockResponse,
        });
      }

      const mockResponse = createMockResponse({
        id: "2",
        code: 404,
        headers: {},
        body: "Not Found",
      });
      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      laravelDebugCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.MEDIUM },
      },
    );

    const findings = executionHistory.flatMap((e) =>
      e.steps.flatMap((s) => s.findings),
    );

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]).toMatchObject({
      name: "Laravel Clockwork Debug Panel",
      severity: "high",
    });
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
        path: "/app/_ignition/health-check",
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
      laravelDebugCheck,
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

  it("should not detect when response is not valid JSON", async () => {
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
        path: "/app/_ignition/health-check",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/html"],
        },
        body: "<html><body>Not JSON</body></html>",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      laravelDebugCheck,
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

  it("should test more endpoints on higher aggressivity", async () => {
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

    await runCheck(laravelDebugCheck, [{ request, response: undefined }], {
      sendHandler,
      config: { aggressivity: ScanAggressivity.HIGH },
    });

    const hasIgnition = testedPaths.some((p) => p.includes("_ignition"));
    const hasClockwork = testedPaths.some((p) => p.includes("__clockwork"));
    const hasTelescope = testedPaths.some((p) => p.includes("telescope"));

    expect(hasIgnition).toBe(true);
    expect(hasClockwork).toBe(true);
    expect(hasTelescope).toBe(true);
  });
});
