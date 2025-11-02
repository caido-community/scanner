import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import gitConfigCheck from "./index";

describe("git-config check", () => {
  it("should detect exposed git config file with valid content", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/index.html",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/app/.git/config",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/plain"],
        },
        body: '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote "origin"]\n\turl = https://github.com/user/repo.git\n[branch "main"]\n\tremote = origin',
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      gitConfigCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "git-config",
        finalOutput: undefined,
        targetRequestId: "1",
        steps: [
          {
            stepName: "setupScan",
            stateBefore: {
              gitFiles: [],
              basePath: "",
            },
            stateAfter: {
              gitFiles: [".git/config"],
              basePath: "/app",
            },
            findings: [],
            result: "continue",
            nextStep: "testGitFile",
          },
          {
            stepName: "testGitFile",
            stateBefore: {
              gitFiles: [".git/config"],
              basePath: "/app",
            },
            stateAfter: {
              gitFiles: [".git/config"],
              basePath: "/app",
            },
            findings: [
              {
                correlation: {
                  requestID: "2",
                },
              },
            ],
            result: "done",
          },
        ],
        status: "completed",
      },
    ]);
  });

  it("should not detect when git file returns 404", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/index.html",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/app/.git/config",
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
      gitConfigCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toEqual([
      {
        checkId: "git-config",
        finalOutput: undefined,
        targetRequestId: "1",
        steps: [
          {
            stepName: "setupScan",
            stateBefore: {
              gitFiles: [],
              basePath: "",
            },
            stateAfter: {
              gitFiles: [".git/config"],
              basePath: "/app",
            },
            findings: [],
            result: "continue",
            nextStep: "testGitFile",
          },
          {
            stepName: "testGitFile",
            stateBefore: {
              gitFiles: [".git/config"],
              basePath: "/app",
            },
            stateAfter: {
              gitFiles: [],
              basePath: "/app",
            },
            findings: [],
            result: "continue",
            nextStep: "testGitFile",
          },
          {
            stepName: "testGitFile",
            stateBefore: {
              gitFiles: [],
              basePath: "/app",
            },
            stateAfter: {
              gitFiles: [],
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

  it("should not detect when file content is not valid git format", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/index.html",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/app/.git/config",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/html"],
        },
        body: "<html><body><h1>Access Denied</h1></body></html>",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      gitConfigCheck,
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

  it("should detect git log file with valid format", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const sendHandler = (spec: any) => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: spec.getPath(),
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: { "Content-Type": ["text/plain"] },
        body: "0000000000000000000000000000000000000000 a1b2c3d4e5f6789012345678901234567890abcd Author Name <email@example.com> 1234567890 +0000\tcommit: Initial commit",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      gitConfigCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.MEDIUM },
      },
    );

    const findings = executionHistory[0].steps.flatMap(
      (step) => step.findings ?? [],
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]).toMatchObject({
      name: "Exposed Git File",
      severity: "medium",
    });
    expect(findings[0].description).toContain("log file");
  });

  it("should detect git HEAD file", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const sendHandler = (spec: any) => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: spec.getPath(),
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: { "Content-Type": ["text/plain"] },
        body: "ref: refs/heads/main",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      gitConfigCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.MEDIUM },
      },
    );

    const findings = executionHistory[0].steps.flatMap(
      (step) => step.findings ?? [],
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]).toMatchObject({
      name: "Exposed Git File",
      severity: "medium",
    });
  });

  it("should flag git config with CRITICAL severity", async () => {
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
        path: "/.git/config",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: { "Content-Type": ["text/plain"] },
        body: '[core]\n\trepositoryformatversion = 0\n[credentials]\n\thelper = store',
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      gitConfigCheck,
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
      name: "Exposed Git File",
      severity: "critical",
    });
    expect(findings[0].description).toContain("configuration file");
    expect(findings[0].description).toContain("credentials");
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
        path: "/.git/config",
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
      gitConfigCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.MEDIUM },
      },
    );

    expect(callCount).toBe(3);
  });

  it("should test all files at HIGH aggressivity", async () => {
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
        path: "/.git/config",
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
      gitConfigCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.HIGH },
      },
    );

    expect(callCount).toBe(6);
  });

  it("should not flag HTML error pages", async () => {
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
        path: "/.git/config",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: { "Content-Type": ["text/html"] },
        body: "<!DOCTYPE html><html><body>Not Found</body></html>",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      gitConfigCheck,
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

  it("should not flag JSON responses", async () => {
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
        path: "/.git/config",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: { "Content-Type": ["application/json"] },
        body: '{"error": "file not found"}',
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      gitConfigCheck,
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
