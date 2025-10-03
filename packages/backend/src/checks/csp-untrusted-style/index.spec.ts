import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import cspUntrustedStyleCheck from "./index";

describe("CSP Untrusted Style Check", () => {
  it("should detect unsafe-inline in style-src", async () => {
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
        "content-security-policy": ["style-src 'self' 'unsafe-inline'"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspUntrustedStyleCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-untrusted-style",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "checkCspUntrustedStyle",
            findings: [
              {
                name: "Content security policy: allows untrusted style execution",
                severity: "medium",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect wildcard in style-src", async () => {
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
        "content-security-policy": ["style-src *"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspUntrustedStyleCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-untrusted-style",
        targetRequestId: "2",
        status: "completed",
        steps: [
          {
            stepName: "checkCspUntrustedStyle",
            findings: [
              {
                name: "Content security policy: allows untrusted style execution",
                severity: "high",
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
        "content-security-policy": ["style-src 'self' data: blob:"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspUntrustedStyleCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-untrusted-style",
        targetRequestId: "3",
        status: "completed",
        steps: [
          {
            stepName: "checkCspUntrustedStyle",
            findings: [
              {
                name: "Content security policy: allows untrusted style execution",
                severity: "medium",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect unsafe-inline in default-src when style-src is missing", async () => {
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
        "content-security-policy": ["default-src 'self' 'unsafe-inline'"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspUntrustedStyleCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-untrusted-style",
        targetRequestId: "4",
        status: "completed",
        steps: [
          {
            stepName: "checkCspUntrustedStyle",
            findings: [
              {
                name: "Content security policy: allows untrusted style execution",
                severity: "medium",
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
        "content-security-policy": ["style-src 'self' https://trusted-cdn.com"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspUntrustedStyleCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-untrusted-style",
        targetRequestId: "5",
        status: "completed",
        steps: [
          {
            stepName: "checkCspUntrustedStyle",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not run when CSP header is missing", async () => {
    const request = createMockRequest({
      id: "6",
      host: "example.com",
      method: "GET",
      path: "/",
    });

    const response = createMockResponse({
      id: "6",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspUntrustedStyleCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-untrusted-style",
        targetRequestId: "6",
        status: "completed",
        steps: [
          {
            stepName: "checkCspUntrustedStyle",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });
});
