import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import webConfigCheck from "./index";

describe("web-config-disclosure check", () => {
  it("should detect valid web.config file", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/page.aspx",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/app/web.config",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/xml"],
        },
        body: '<?xml version="1.0"?>\n<configuration>\n  <system.web>\n    <compilation debug="true" />\n  </system.web>\n</configuration>',
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      webConfigCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "web-config-disclosure",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "setupScan",
            result: "continue",
            nextStep: "testWebConfig",
          },
          {
            stepName: "testWebConfig",
            findings: [
              {
                name: "Web.config File Disclosed",
                severity: "high",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not detect when web.config returns 404", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/page.aspx",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/app/web.config",
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
      webConfigCheck,
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

  it("should not detect when body lacks configuration elements", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/app/page.aspx",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/app/web.config",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/xml"],
        },
        body: '<?xml version="1.0"?>\n<root><item>not a config</item></root>',
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      webConfigCheck,
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
