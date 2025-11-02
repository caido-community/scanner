import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import exposedEnvCheck from "./index";

describe("exposed-env check", () => {
  it("should detect exposed .env file with valid content", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/page.php",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/app/.env",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/plain"],
        },
        body: "API_KEY=secret123",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      exposedEnvCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "exposed-env",
        finalOutput: undefined,
        targetRequestId: "1",
        steps: [
          {
            stepName: "setupScan",
            stateBefore: {
              envFiles: [],
              basePath: "",
            },
            stateAfter: {
              envFiles: [".env"],
              basePath: "/app",
            },
            findings: [],
            result: "continue",
            nextStep: "testEnvFile",
          },
          {
            stepName: "testEnvFile",
            stateBefore: {
              envFiles: [".env"],
              basePath: "/app",
            },
            stateAfter: {
              envFiles: [],
              basePath: "/app",
            },
            findings: [
              {
                correlation: {
                  requestID: "2",
                },
              },
            ],
            result: "continue",
            nextStep: "testEnvFile",
          },
          {
            stepName: "testEnvFile",
            stateBefore: {
              envFiles: [],
              basePath: "/app",
            },
            stateAfter: {
              envFiles: [],
              basePath: "/app",
            },
            findings: [],
            result: "done",
          },
        ],
        status: "completed",
      },
    ]);
  });

  it("should not detect when .env file returns 404", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/page.php",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/app/.env",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 404,
        headers: {
          "Content-Type": ["text/html"],
        },
        body: "Not Found",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      exposedEnvCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toEqual([
      {
        checkId: "exposed-env",
        finalOutput: undefined,
        targetRequestId: "1",
        steps: [
          {
            stepName: "setupScan",
            stateBefore: {
              envFiles: [],
              basePath: "",
            },
            stateAfter: {
              envFiles: [".env"],
              basePath: "/app",
            },
            findings: [],
            result: "continue",
            nextStep: "testEnvFile",
          },
          {
            stepName: "testEnvFile",
            stateBefore: {
              envFiles: [".env"],
              basePath: "/app",
            },
            stateAfter: {
              envFiles: [],
              basePath: "/app",
            },
            findings: [],
            result: "continue",
            nextStep: "testEnvFile",
          },
          {
            stepName: "testEnvFile",
            stateBefore: {
              envFiles: [],
              basePath: "/app",
            },
            stateAfter: {
              envFiles: [],
              basePath: "/app",
            },
            findings: [],
            result: "done",
          },
        ],
        status: "completed",
      },
    ]);
  });

  it("should not detect when file content is not valid env format", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/page.php",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/app/.env",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/html"],
        },
        body: "<html><body><h1>Welcome</h1></body></html>",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      exposedEnvCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    const findings = executionHistory[0].steps.flatMap(
      (step) => step.findings ?? [],
    );
    expect(findings).toHaveLength(0);
  });

  it("should detect .env with DATABASE_URL", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/.env",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: { "Content-Type": ["text/plain"] },
        body: "DATABASE_URL=postgres://user:pass@localhost/db",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      exposedEnvCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    const findings = executionHistory[0].steps.flatMap(
      (step) => step.findings ?? [],
    );
    expect(findings[0]).toMatchObject({
      name: "Exposed Environment File",
      severity: "critical",
    });
    expect(findings[0].description).toContain("Environment file");
    expect(findings[0].description).toContain("credentials");
  });

  it("should detect .env with TOKEN", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/.env",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: { "Content-Type": ["text/plain"] },
        body: "GITHUB_TOKEN=ghp_secret123",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      exposedEnvCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    const findings = executionHistory[0].steps.flatMap(
      (step) => step.findings ?? [],
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe("critical");
  });

  it("should detect .env with SECRET", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/.env",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: { "Content-Type": ["text/plain"] },
        body: "APP_SECRET=mysecret123",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      exposedEnvCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    const findings = executionHistory[0].steps.flatMap(
      (step) => step.findings ?? [],
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe("critical");
  });

  it("should detect .env with PASS", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/.env",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: { "Content-Type": ["text/plain"] },
        body: "DB_PASSWORD=password123",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      exposedEnvCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    const findings = executionHistory[0].steps.flatMap(
      (step) => step.findings ?? [],
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  it("should test multiple files at MEDIUM aggressivity", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    let callCount = 0;
    const sendHandler = () => {
      callCount++;
      const mockRequest = createMockRequest({
        id: String(callCount + 1),
        host: "example.com",
        method: "GET",
        path: "/.env",
      });

      const mockResponse = createMockResponse({
        id: String(callCount + 1),
        code: 404,
        headers: {},
        body: "Not Found",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    await runCheck(
      exposedEnvCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.MEDIUM },
      },
    );

    expect(callCount).toBe(4);
  });

  it("should test all env files at HIGH aggressivity", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    let callCount = 0;
    const sendHandler = () => {
      callCount++;
      const mockRequest = createMockRequest({
        id: String(callCount + 1),
        host: "example.com",
        method: "GET",
        path: "/.env",
      });

      const mockResponse = createMockResponse({
        id: String(callCount + 1),
        code: 404,
        headers: {},
        body: "Not Found",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    await runCheck(
      exposedEnvCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.HIGH },
      },
    );

    expect(callCount).toBe(13);
  });

  it("should not flag files larger than 500 bytes", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/.env",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: { "Content-Type": ["text/plain"] },
        body: "API_KEY=value\n" + "x".repeat(500),
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      exposedEnvCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    const findings = executionHistory[0].steps.flatMap(
      (step) => step.findings ?? [],
    );
    expect(findings).toHaveLength(0);
  });

  it("should not flag empty files", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/.env",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: { "Content-Type": ["text/plain"] },
        body: "   ",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      exposedEnvCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    const findings = executionHistory[0].steps.flatMap(
      (step) => step.findings ?? [],
    );
    expect(findings).toHaveLength(0);
  });
});
