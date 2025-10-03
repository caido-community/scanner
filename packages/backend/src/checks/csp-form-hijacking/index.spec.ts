import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import cspFormHijackingCheck from "./index";

describe("CSP Form Hijacking Check", () => {
  it("should detect missing form-action directive", async () => {
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
        "content-security-policy": ["default-src 'self'; script-src 'self'"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspFormHijackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-form-hijacking",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "checkCspFormHijacking",
            findings: [
              {
                name: "Content security policy: allows form hijacking",
                severity: "medium",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect wildcard in form-action", async () => {
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
        "content-security-policy": ["form-action *"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspFormHijackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-form-hijacking",
        targetRequestId: "2",
        status: "completed",
        steps: [
          {
            stepName: "checkCspFormHijacking",
            findings: [
              {
                name: "Content security policy: allows form hijacking",
                severity: "high",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect data: and blob: sources in form-action", async () => {
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
        "content-security-policy": ["form-action 'self' data: blob:"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspFormHijackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-form-hijacking",
        targetRequestId: "3",
        status: "completed",
        steps: [
          {
            stepName: "checkCspFormHijacking",
            findings: [
              {
                name: "Content security policy: allows form hijacking",
                severity: "medium",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect HTTP sources in form-action", async () => {
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
        "content-security-policy": ["form-action 'self' http://example.com"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspFormHijackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-form-hijacking",
        targetRequestId: "4",
        status: "completed",
        steps: [
          {
            stepName: "checkCspFormHijacking",
            findings: [
              {
                name: "Content security policy: allows form hijacking",
                severity: "low",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should find no issues with secure form-action", async () => {
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
        "content-security-policy": ["form-action 'self' https://trusted.com"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspFormHijackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-form-hijacking",
        targetRequestId: "5",
        status: "completed",
        steps: [
          {
            stepName: "checkCspFormHijacking",
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

    const executionHistory = await runCheck(cspFormHijackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-form-hijacking",
        targetRequestId: "6",
        status: "completed",
        steps: [
          {
            stepName: "checkCspFormHijacking",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });
});
