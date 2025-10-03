import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import cspUntrustedScriptCheck from "./index";

describe("CSP Untrusted Script Check", () => {
  it("should detect unsafe-inline in script-src", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: {
        "content-type": ["text/html"],
        "content-security-policy": ["script-src 'self' 'unsafe-inline'"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspUntrustedScriptCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-untrusted-script",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "checkCspUntrustedScript",
            findings: [
              {
                name: "Content security policy: allows untrusted script execution",
                severity: "high",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect unsafe-eval in script-src", async () => {
    const request = createMockRequest({
      id: "2",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "2",
      code: 200,
      headers: {
        "content-type": ["text/html"],
        "content-security-policy": ["script-src 'self' 'unsafe-eval'"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspUntrustedScriptCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-untrusted-script",
        targetRequestId: "2",
        status: "completed",
        steps: [
          {
            stepName: "checkCspUntrustedScript",
            findings: [
              {
                name: "Content security policy: allows untrusted script execution",
                severity: "high",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect wildcard in script-src", async () => {
    const request = createMockRequest({
      id: "3",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "3",
      code: 200,
      headers: {
        "content-type": ["text/html"],
        "content-security-policy": ["script-src *"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspUntrustedScriptCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-untrusted-script",
        targetRequestId: "3",
        status: "completed",
        steps: [
          {
            stepName: "checkCspUntrustedScript",
            findings: [
              {
                name: "Content security policy: allows untrusted script execution",
                severity: "critical",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect data: and blob: sources", async () => {
    const request = createMockRequest({
      id: "4",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "4",
      code: 200,
      headers: {
        "content-type": ["text/html"],
        "content-security-policy": ["script-src 'self' data: blob:"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspUntrustedScriptCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-untrusted-script",
        targetRequestId: "4",
        status: "completed",
        steps: [
          {
            stepName: "checkCspUntrustedScript",
            findings: [
              {
                name: "Content security policy: allows untrusted script execution",
                severity: "high",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect unsafe-inline in default-src when script-src is missing", async () => {
    const request = createMockRequest({
      id: "5",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "5",
      code: 200,
      headers: {
        "content-type": ["text/html"],
        "content-security-policy": ["default-src 'self' 'unsafe-inline'"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspUntrustedScriptCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-untrusted-script",
        targetRequestId: "5",
        status: "completed",
        steps: [
          {
            stepName: "checkCspUntrustedScript",
            findings: [
              {
                name: "Content security policy: allows untrusted script execution",
                severity: "high",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should find no issues with secure CSP", async () => {
    const request = createMockRequest({
      id: "6",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "6",
      code: 200,
      headers: {
        "content-type": ["text/html"],
        "content-security-policy": ["script-src 'self' https://trusted-cdn.com"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspUntrustedScriptCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-untrusted-script",
        targetRequestId: "6",
        status: "completed",
        steps: [
          {
            stepName: "checkCspUntrustedScript",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not run when CSP header is missing", async () => {
    const request = createMockRequest({
      id: "7",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "7",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspUntrustedScriptCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-untrusted-script",
        targetRequestId: "7",
        status: "completed",
        steps: [
          {
            stepName: "checkCspUntrustedScript",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });
});
