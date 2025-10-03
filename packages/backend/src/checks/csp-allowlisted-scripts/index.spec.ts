import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import cspAllowlistedScriptsCheck from "./index";

describe("CSP Allowlisted Scripts Check", () => {
  it("should detect too many external domains", async () => {
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
        "content-security-policy": [
          "script-src 'self' https://cdn1.com https://cdn2.com https://cdn3.com https://cdn4.com https://cdn5.com https://cdn6.com",
        ],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-allowlisted-scripts",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "checkCspAllowlistedScripts",
            findings: expect.arrayContaining([
              expect.objectContaining({
                name: "Content security policy: allowlisted script resources",
                severity: "medium",
              }),
            ]),
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect multiple CDN domains", async () => {
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
        "content-security-policy": [
          "script-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://unpkg.com https://cdn.example.com",
        ],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-allowlisted-scripts",
        targetRequestId: "2",
        status: "completed",
        steps: [
          {
            stepName: "checkCspAllowlistedScripts",
            findings: [
              {
                name: "Content security policy: allowlisted script resources",
                severity: "low",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect wildcard subdomains", async () => {
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
        "content-security-policy": ["script-src 'self' *.google.com *.microsoft.com"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-allowlisted-scripts",
        targetRequestId: "3",
        status: "completed",
        steps: [
          {
            stepName: "checkCspAllowlistedScripts",
            findings: expect.arrayContaining([
              expect.objectContaining({
                name: "Content security policy: allowlisted script resources",
                severity: "medium",
              }),
            ]),
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect HTTP sources", async () => {
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
        "content-security-policy": ["script-src 'self' http://insecure.com"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-allowlisted-scripts",
        targetRequestId: "4",
        status: "completed",
        steps: [
          {
            stepName: "checkCspAllowlistedScripts",
            findings: [
              {
                name: "Content security policy: allowlisted script resources",
                severity: "low",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect broad domains", async () => {
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
        "content-security-policy": ["script-src 'self' *.google.com *.microsoft.com"],
      },
      body: "<html><body>Test</body></html>",
    });

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-allowlisted-scripts",
        targetRequestId: "5",
        status: "completed",
        steps: [
          {
            stepName: "checkCspAllowlistedScripts",
            findings: expect.arrayContaining([
              expect.objectContaining({
                name: "Content security policy: allowlisted script resources",
                severity: "low",
              }),
            ]),
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

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-allowlisted-scripts",
        targetRequestId: "6",
        status: "completed",
        steps: [
          {
            stepName: "checkCspAllowlistedScripts",
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

    const executionHistory = await runCheck(cspAllowlistedScriptsCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "csp-allowlisted-scripts",
        targetRequestId: "7",
        status: "completed",
        steps: [
          {
            stepName: "checkCspAllowlistedScripts",
            findings: [],
            result: "done",
          },
        ],
      },
    ]);
  });
});
