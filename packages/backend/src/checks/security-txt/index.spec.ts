import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import securityTxtCheck from "./index";

describe("security-txt check", () => {
  it("should detect valid security.txt file", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page.html",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/.well-known/security.txt",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/plain"],
        },
        body: "Contact: security@example.com\nExpires: 2025-12-31T23:59:59.000Z\nPreferred-Languages: en",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      securityTxtCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "security-txt",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "setupScan",
            result: "continue",
            nextStep: "testSecurityTxt",
          },
          {
            stepName: "testSecurityTxt",
            findings: [
              {
                name: "Security.txt File Found",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not detect when security.txt returns 404", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page.html",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/.well-known/security.txt",
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
      securityTxtCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    const allFindings =
      executionHistory[0]?.steps.flatMap((step) => step.findings) ?? [];
    expect(allFindings).toEqual([]);
  });

  it("should not detect when body lacks Contact field", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page.html",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/.well-known/security.txt",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/plain"],
        },
        body: "This is just a random text file without the required fields",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      securityTxtCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    const allFindings =
      executionHistory[0]?.steps.flatMap((step) => step.findings) ?? [];
    expect(allFindings).toEqual([]);
  });
});
