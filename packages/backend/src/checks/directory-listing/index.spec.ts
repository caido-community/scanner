import {
  createMockRequest,
  createMockResponse,
  runCheck,
  ScanAggressivity,
} from "engine";
import { describe, expect, it } from "vitest";

import directoryListingCheck from "./index";

describe("directory-listing check", () => {
  describe("Detection", () => {
    it("should detect Apache/Tomcat directory listing", async () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/uploads/file.txt",
      });

      const sendHandler = () => {
        const mockRequest = createMockRequest({
          id: "2",
          host: "example.com",
          method: "GET",
          path: "/uploads/",
        });

        const mockResponse = createMockResponse({
          id: "2",
          code: 200,
          headers: { "content-type": ["text/html"] },
          body: '<html><head><title>Directory Listing - Apache</title></head><body>Directory Listing for Apache</body></html>',
        });

        return Promise.resolve({ request: mockRequest, response: mockResponse });
      };

      const executionHistory = await runCheck(
        directoryListingCheck,
        [{ request, response: undefined }],
        { sendHandler, config: { aggressivity: ScanAggressivity.LOW } },
      );

      expect(executionHistory[0].steps).toContainEqual(
        expect.objectContaining({
          stepName: "testCandidate",
          findings: [
            expect.objectContaining({
              name: "Directory Listing Enabled",
              severity: "medium",
            }),
          ],
        }),
      );
    });

    it("should detect IIS Parent Directory marker", async () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/docs/",
      });

      const sendHandler = () => {
        const mockRequest = createMockRequest({
          id: "2",
          host: "example.com",
          method: "GET",
          path: "/docs/",
        });

        const mockResponse = createMockResponse({
          id: "2",
          code: 200,
          headers: { "content-type": ["text/html"] },
          body: '<html><body><a href="../">Parent Directory</a></body></html>',
        });

        return Promise.resolve({ request: mockRequest, response: mockResponse });
      };

      const executionHistory = await runCheck(
        directoryListingCheck,
        [{ request, response: undefined }],
        { sendHandler, config: { aggressivity: ScanAggressivity.LOW } },
      );

      expect(executionHistory[0].steps).toContainEqual(
        expect.objectContaining({
          findings: [
            expect.objectContaining({
              name: "Directory Listing Enabled",
              severity: "medium",
            }),
          ],
        }),
      );
    });

    it("should detect generic directory + IMG pattern (low confidence)", async () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/files/",
      });

      const sendHandler = () => {
        const mockRequest = createMockRequest({
          id: "2",
          host: "example.com",
          method: "GET",
          path: "/files/",
        });

        const mockResponse = createMockResponse({
          id: "2",
          code: 200,
          headers: { "content-type": ["text/html"] },
          body: '<html><body>Directory files <IMG =icon.png></body></html>',
        });

        return Promise.resolve({ request: mockRequest, response: mockResponse });
      };

      const executionHistory = await runCheck(
        directoryListingCheck,
        [{ request, response: undefined }],
        { sendHandler, config: { aggressivity: ScanAggressivity.LOW } },
      );

      expect(executionHistory[0].steps).toContainEqual(
        expect.objectContaining({
          findings: [
            expect.objectContaining({
              name: "Directory Listing Enabled",
              severity: "low",
            }),
          ],
        }),
      );
    });

    it("should test parent directories at MEDIUM aggressivity", async () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/a/b/file.txt",
      });

      let callCount = 0;
      const sendHandler = () => {
        callCount++;
        const mockRequest = createMockRequest({
          id: String(callCount + 1),
          host: "example.com",
          method: "GET",
          path: callCount === 1 ? "/a/b/" : "/a/",
        });

        const mockResponse = createMockResponse({
          id: String(callCount + 1),
          code: 404,
          headers: {},
          body: "Not Found",
        });

        return Promise.resolve({ request: mockRequest, response: mockResponse });
      };

      const executionHistory = await runCheck(
        directoryListingCheck,
        [{ request, response: undefined }],
        { sendHandler, config: { aggressivity: ScanAggressivity.MEDIUM } },
      );

      expect(callCount).toBe(2);
      expect(executionHistory[0].status).toBe("completed");
    });
  });

  describe("False Positives", () => {
    it("should not flag 404 responses", async () => {
      const request = createMockRequest({
        id: "10",
        host: "example.com",
        method: "GET",
        path: "/images/pic.png",
      });

      const sendHandler = () => {
        const mockRequest = createMockRequest({
          id: "11",
          host: "example.com",
          method: "GET",
          path: "/images/",
        });
        const mockResponse = createMockResponse({
          id: "11",
          code: 404,
          headers: {},
          body: "Not Found",
        });
        return Promise.resolve({ request: mockRequest, response: mockResponse });
      };

      const executionHistory = await runCheck(
        directoryListingCheck,
        [{ request, response: undefined }],
        { sendHandler, config: { aggressivity: ScanAggressivity.LOW } },
      );

      const findings = executionHistory[0].steps.flatMap(
        (step) => step.findings ?? [],
      );
      expect(findings).toHaveLength(0);
    });

    it("should not flag 403 responses", async () => {
      const request = createMockRequest({
        id: "10",
        host: "example.com",
        method: "GET",
        path: "/private/",
      });

      const sendHandler = () => {
        const mockRequest = createMockRequest({
          id: "11",
          host: "example.com",
          method: "GET",
          path: "/private/",
        });
        const mockResponse = createMockResponse({
          id: "11",
          code: 403,
          headers: {},
          body: "Forbidden",
        });
        return Promise.resolve({ request: mockRequest, response: mockResponse });
      };

      const executionHistory = await runCheck(
        directoryListingCheck,
        [{ request, response: undefined }],
        { sendHandler, config: { aggressivity: ScanAggressivity.LOW } },
      );

      const findings = executionHistory[0].steps.flatMap(
        (step) => step.findings ?? [],
      );
      expect(findings).toHaveLength(0);
    });

    it("should not flag normal HTML without directory markers", async () => {
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
          path: "/",
        });

        const mockResponse = createMockResponse({
          id: "2",
          code: 200,
          headers: { "content-type": ["text/html"] },
          body: "<html><body><h1>Welcome</h1><p>Normal page content</p></body></html>",
        });

        return Promise.resolve({ request: mockRequest, response: mockResponse });
      };

      const executionHistory = await runCheck(
        directoryListingCheck,
        [{ request, response: undefined }],
        { sendHandler, config: { aggressivity: ScanAggressivity.LOW } },
      );

      const findings = executionHistory[0].steps.flatMap(
        (step) => step.findings ?? [],
      );
      expect(findings).toHaveLength(0);
    });
  });

  describe("Edge Cases", () => {
    it("should include evidence in finding description", async () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/uploads/",
      });

      const sendHandler = () => {
        const mockRequest = createMockRequest({
          id: "2",
          host: "example.com",
          method: "GET",
          path: "/uploads/",
        });

        const mockResponse = createMockResponse({
          id: "2",
          code: 200,
          headers: { "content-type": ["text/html"] },
          body: '<html><body>Directory Listing - Apache Server</body></html>',
        });

        return Promise.resolve({ request: mockRequest, response: mockResponse });
      };

      const executionHistory = await runCheck(
        directoryListingCheck,
        [{ request, response: undefined }],
        { sendHandler, config: { aggressivity: ScanAggressivity.LOW } },
      );

      const finding = executionHistory[0].steps.flatMap(
        (step) => step.findings ?? [],
      )[0];
      expect(finding.description).toContain("Evidence:");
      expect(finding.description).toContain("sensitive files");
    });

    it("should convert file path to directory path", async () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/docs/readme.txt",
      });

      const sendHandler = (spec: any) => {
        expect(spec.getPath()).toBe("/docs/");

        const mockRequest = createMockRequest({
          id: "2",
          host: "example.com",
          method: "GET",
          path: "/docs/",
        });

        const mockResponse = createMockResponse({
          id: "2",
          code: 404,
          headers: {},
          body: "Not Found",
        });

        return Promise.resolve({ request: mockRequest, response: mockResponse });
      };

      await runCheck(
        directoryListingCheck,
        [{ request, response: undefined }],
        { sendHandler, config: { aggressivity: ScanAggressivity.LOW } },
      );
    });
  });
});
