import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import svnCheck from "./index";

describe("svn-disclosure check", () => {
  it("should detect valid .svn/entries file", async () => {
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
        path: "/app/.svn/entries",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/plain"],
        },
        body: "10\n\ndir\n12345\nhttps://svn.example.com/repo/trunk",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      svnCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "svn-disclosure",
        targetRequestId: "1",
        status: "completed",
      },
    ]);

    const allFindings =
      executionHistory[0]?.steps.flatMap((step) => step.findings) ?? [];
    expect(allFindings).toHaveLength(1);
    expect(allFindings[0]).toMatchObject({
      name: "SVN Repository Disclosed",
      severity: "medium",
    });
  });

  it("should not detect when .svn/entries returns 404", async () => {
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
        path: "/app/.svn/entries",
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
      svnCheck,
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

  it("should not detect when entries content is invalid", async () => {
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
        path: "/app/.svn/entries",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/html"],
        },
        body: "<html><body>Not SVN</body></html>",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      svnCheck,
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
