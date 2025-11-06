import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import aspNetTracingCheck from "./index";

const runTracingCheck = async (
  path: string,
  code: number,
  body: string,
): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "req",
    host: "example.com",
    method: "GET",
    path,
  });

  const response = createMockResponse({
    id: "res",
    code,
    headers: { "content-type": ["text/html"] },
    body,
  });

  const execution = await runCheck(aspNetTracingCheck, [
    { request, response },
  ]);

  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("ASP.NET tracing check", () => {
  describe("Detection", () => {
    it("should detect trace.axd with Trace Information marker", async () => {
      const findings = await runTracingCheck(
        "/trace.axd",
        200,
        "<html><title>Trace Information</title></html>",
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        name: "ASP.NET tracing enabled",
        severity: "medium",
      });
    });

    it("should detect trace.axd with Request Details marker", async () => {
      const findings = await runTracingCheck(
        "/trace.axd",
        200,
        "<html><body>Request Details for session</body></html>",
      );

      expect(findings).toHaveLength(1);
    });

    it("should detect trace.axd with Trace.axd marker in content", async () => {
      const findings = await runTracingCheck(
        "/trace.axd",
        200,
        "<html><body>Trace.axd page content</body></html>",
      );

      expect(findings).toHaveLength(1);
    });

    it("should be case-insensitive for path matching", async () => {
      const findings = await runTracingCheck(
        "/Trace.AXD",
        200,
        "<html>Trace Information</html>",
      );

      expect(findings).toHaveLength(1);
    });

    it("should be case-insensitive for content matching", async () => {
      const findings = await runTracingCheck(
        "/trace.axd",
        200,
        "<html>TRACE INFORMATION AND REQUEST DETAILS</html>",
      );

      expect(findings).toHaveLength(1);
    });
  });

  describe("False Positives", () => {
    it("should not flag 404 responses", async () => {
      const findings = await runTracingCheck(
        "/trace.axd",
        404,
        "Not found",
      );

      expect(findings).toHaveLength(0);
    });

    it("should not flag 403 responses", async () => {
      const findings = await runTracingCheck(
        "/trace.axd",
        403,
        "Forbidden",
      );

      expect(findings).toHaveLength(0);
    });

    it("should not flag 200 responses without trace markers", async () => {
      const findings = await runTracingCheck(
        "/trace.axd",
        200,
        "<html><body>Some other content</body></html>",
      );

      expect(findings).toHaveLength(0);
    });

    it("should not flag non-trace.axd paths", async () => {
      const findings = await runTracingCheck(
        "/trace.html",
        200,
        "<html>Trace Information</html>",
      );

      expect(findings).toHaveLength(0);
    });
  });

  describe("Edge Cases", () => {
    it("should not run when response is missing", async () => {
      const request = createMockRequest({
        id: "req",
        host: "example.com",
        method: "GET",
        path: "/trace.axd",
      });

      const execution = await runCheck(aspNetTracingCheck, [
        { request, response: undefined },
      ]);

      const findings =
        execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
      expect(findings).toHaveLength(0);
    });

    it("should include security guidance in description", async () => {
      const findings = await runTracingCheck(
        "/trace.axd",
        200,
        "<html>Trace Information</html>",
      );

      expect(findings[0].description).toContain("trace.axd");
      expect(findings[0].description).toContain("sensitive data");
      expect(findings[0].description).toContain("Web.config");
    });
  });
});
