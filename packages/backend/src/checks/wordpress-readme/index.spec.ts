import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import wordpressReadmeCheck from "./index";

describe("wordpress-readme check", () => {
  it("should detect WordPress readme.html", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/index.php",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/readme.html",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/html"],
        },
        body: "<!DOCTYPE html><html><head><title>WordPress &rsaquo; ReadMe</title></head><body><h1>WordPress</h1><p>Version 6.4.2</p></body></html>",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      wordpressReadmeCheck,
      [{ request, response: undefined }],
      {
        sendHandler,
        config: { aggressivity: ScanAggressivity.LOW },
      },
    );

    expect(executionHistory).toMatchObject([
      {
        checkId: "wordpress-readme",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "setupScan",
            result: "continue",
            nextStep: "testReadme",
          },
          {
            stepName: "testReadme",
            findings: [
              {
                name: "WordPress Readme Exposed",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not detect when readme.html returns 404", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/index.php",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/readme.html",
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
      wordpressReadmeCheck,
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

  it("should not detect when body does not mention WordPress", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/index.php",
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "GET",
        path: "/readme.html",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: {
          "Content-Type": ["text/html"],
        },
        body: "<!DOCTYPE html><html><body><h1>Welcome to My Application</h1></body></html>",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runCheck(
      wordpressReadmeCheck,
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
