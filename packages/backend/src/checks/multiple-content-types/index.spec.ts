import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import multipleContentTypesCheck from "./index";

const buildTarget = (headers: Record<string, string[]>) => {
  const request = createMockRequest({
    id: "req-1",
    host: "example.com",
    method: "GET",
    path: "/resource",
    headers: { Host: ["example.com"] },
  });

  const response = createMockResponse({
    id: "res-1",
    code: 200,
    headers,
    body: "<html></html>",
  });

  return { request, response };
};

const collectFindings = async (
  headers: Record<string, string[]>,
): Promise<unknown[]> => {
  const target = buildTarget(headers);
  const execution = await runCheck(multipleContentTypesCheck, [target]);
  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Multiple Content-Type headers check", () => {
  describe("Detection", () => {
    it("reports when multiple distinct content types are present", async () => {
      const findings = await collectFindings({
        "content-type": ["text/html", "application/json"],
      });

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        name: "Multiple Content-Type headers detected",
        severity: "medium",
      });
    });

    it("reports when multiple content types are comma-separated in a single header", async () => {
      const findings = await collectFindings({
        "content-type": ["text/html, application/json"],
      });

      expect(findings).toHaveLength(1);
    });

    it("reports three or more distinct content types", async () => {
      const findings = await collectFindings({
        "content-type": ["text/html", "application/json", "text/plain"],
      });

      expect(findings).toHaveLength(1);
      expect(findings[0].description).toContain("text/html");
      expect(findings[0].description).toContain("application/json");
      expect(findings[0].description).toContain("text/plain");
    });

    it("reports mixed headers and comma-separated values", async () => {
      const findings = await collectFindings({
        "content-type": ["text/html, application/json", "text/xml"],
      });

      expect(findings).toHaveLength(1);
    });

    it("detects conflicting types with charset parameters", async () => {
      const findings = await collectFindings({
        "content-type": [
          "text/html; charset=utf-8",
          "application/json; charset=utf-8",
        ],
      });

      expect(findings).toHaveLength(1);
    });
  });

  describe("False Positive Prevention", () => {
    it("does not report when only one content type is present", async () => {
      const findings = await collectFindings({
        "content-type": ["text/html"],
      });

      expect(findings).toHaveLength(0);
    });

    it("does not report duplicate identical content types", async () => {
      const findings = await collectFindings({
        "content-type": ["text/html", "text/html"],
      });

      expect(findings).toHaveLength(0);
    });

    it("does not report case variations of the same type", async () => {
      const findings = await collectFindings({
        "content-type": ["text/html", "TEXT/HTML", "Text/Html"],
      });

      expect(findings).toHaveLength(0);
    });

    it("does not report duplicate content types with same parameters", async () => {
      const findings = await collectFindings({
        "content-type": [
          "text/html; charset=utf-8",
          "text/html; charset=utf-8",
        ],
      });

      expect(findings).toHaveLength(0);
    });
  });

  describe("Edge Cases", () => {
    it("handles empty content-type header gracefully", async () => {
      const findings = await collectFindings({
        "content-type": [],
      });

      expect(findings).toHaveLength(0);
    });

    it("handles whitespace in comma-separated values", async () => {
      const findings = await collectFindings({
        "content-type": ["text/html  ,   application/json  "],
      });

      expect(findings).toHaveLength(1);
    });

    it("includes guidance about returning single Content-Type", async () => {
      const findings = await collectFindings({
        "content-type": ["text/html", "application/json"],
      });

      expect(findings[0].description).toContain("single, unambiguous");
      expect(findings[0].description).toContain("MIME confusion");
    });
  });
});
