import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import dsStoreCheck from "./index";

describe("ds-store-disclosure check", () => {
  it("should detect .DS_Store file with Bud1 magic", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/page.html",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/app/.DS_Store",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["application/octet-stream"],
        },
        body: "\x00\x00\x00\x01Bud1\x00\x00\x10\x00",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      dsStoreCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "ds-store-disclosure",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "setupScan",
            result: "continue",
            nextStep: "testDsStore",
          },
          {
            stepName: "testDsStore",
            findings: [
              {
                name: "DS_Store File Disclosed",
                severity: "medium",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not detect when .DS_Store returns 404", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/page.html",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/app/.DS_Store",
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
      dsStoreCheck,
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

  it("should not detect when body is too short", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/page.html",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/app/.DS_Store",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {},
        body: "ab",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      dsStoreCheck,
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
