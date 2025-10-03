import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import cspClickjackingCheck from "./index";

describe("CSP Clickjacking Check", () => {
  it("should detect missing frame-ancestors directive", async () => {
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

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-clickjacking",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "checkCspClickjacking",
            findings: [
              {
                name: "Content security policy: allows clickjacking",
                severity: "medium",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect wildcard in frame-ancestors", async () => {
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
        "content-security-policy": ["frame-ancestors *"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-clickjacking",
        targetRequestId: "2",
        status: "completed",
        steps: [
          {
            stepName: "checkCspClickjacking",
            findings: [
              {
                name: "Content security policy: allows clickjacking",
                severity: "high",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect data: and blob: sources in frame-ancestors", async () => {
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
        "content-security-policy": ["frame-ancestors 'self' data: blob:"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-clickjacking",
        targetRequestId: "3",
        status: "completed",
        steps: [
          {
            stepName: "checkCspClickjacking",
            findings: [
              {
                name: "Content security policy: allows clickjacking",
                severity: "medium",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect HTTP sources in frame-ancestors", async () => {
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
        "content-security-policy": ["frame-ancestors 'self' http://example.com"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-clickjacking",
        targetRequestId: "4",
        status: "completed",
        steps: [
          {
            stepName: "checkCspClickjacking",
            findings: [
              {
                name: "Content security policy: allows clickjacking",
                severity: "low",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should find no issues with secure frame-ancestors", async () => {
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
        "content-security-policy": ["frame-ancestors 'none'"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-clickjacking",
        targetRequestId: "5",
        status: "completed",
        steps: [
          {
            stepName: "checkCspClickjacking",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should find no issues with 'self' frame-ancestors", async () => {
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
        "content-security-policy": ["frame-ancestors 'self' https://trusted.com"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-clickjacking",
        targetRequestId: "6",
        status: "completed",
        steps: [
          {
            stepName: "checkCspClickjacking",
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

    const executionHistory = await runCheck(cspClickjackingCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-clickjacking",
        targetRequestId: "7",
        status: "completed",
        steps: [
          {
            stepName: "checkCspClickjacking",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });
});
