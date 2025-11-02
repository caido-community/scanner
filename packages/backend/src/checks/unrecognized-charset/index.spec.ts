import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import unrecognizedCharsetCheck from "./index";

const runCharsetCheck = async (
  contentType: string,
  body: string,
): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "req",
    host: "example.com",
    method: "GET",
    path: "/",
  });

  const response = createMockResponse({
    id: "res",
    code: 200,
    headers: { "content-type": [contentType] },
    body,
  });

  const execution = await runCheck(unrecognizedCharsetCheck, [
    { request, response },
  ]);

  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("HTML uses unrecognized charset check", () => {
  describe("Detection", () => {
    it("should detect unrecognized charset in Content-Type header", async () => {
      const findings = await runCharsetCheck(
        "text/html; charset=foo-unknown",
        "<html><body>Hello</body></html>",
      );

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        name: "HTML uses unrecognized charset",
        severity: "low",
      });
      expect(findings[0].description).toContain("foo-unknown");
    });

    it("should detect unrecognized charset in meta charset tag", async () => {
      const findings = await runCharsetCheck(
        "text/html",
        `<html><head><meta charset="foo-unknown"></head><body>Hi</body></html>`,
      );

      expect(findings).toHaveLength(1);
      expect(findings[0].description).toContain("meta tag");
      expect(findings[0].description).toContain("foo-unknown");
    });

    it("should detect unrecognized charset in meta http-equiv tag", async () => {
      const findings = await runCharsetCheck(
        "text/html",
        `<html><head><meta http-equiv="content-type" content="text/html; charset=bar-unknown"></head></html>`,
      );

      expect(findings).toHaveLength(1);
      expect(findings[0].description).toContain("bar-unknown");
    });

    it("should detect multiple unrecognized charsets", async () => {
      const findings = await runCharsetCheck(
        "text/html; charset=unknown-1",
        `<html><head><meta charset="unknown-2"></head><body>Hi</body></html>`,
      );

      expect(findings).toHaveLength(1);
      expect(findings[0].description).toContain("unknown-1");
      expect(findings[0].description).toContain("unknown-2");
    });
  });

  describe("False Positives", () => {
    it("should not flag recognized UTF-8 charset", async () => {
      const findings = await runCharsetCheck(
        "text/html; charset=UTF-8",
        `<html><head><meta charset="utf-8"></head><body>Hi</body></html>`,
      );

      expect(findings).toHaveLength(0);
    });

    it("should not flag recognized ISO-8859 charsets", async () => {
      const findings = await runCharsetCheck(
        "text/html; charset=ISO-8859-1",
        "<html><body>Hello</body></html>",
      );

      expect(findings).toHaveLength(0);
    });

    it("should not flag recognized Windows charsets", async () => {
      const findings = await runCharsetCheck(
        "text/html; charset=windows-1252",
        "<html><body>Hello</body></html>",
      );

      expect(findings).toHaveLength(0);
    });

    it("should not flag non-HTML responses", async () => {
      const findings = await runCharsetCheck(
        "application/json; charset=foo-unknown",
        '{"data": "value"}',
      );

      expect(findings).toHaveLength(0);
    });

    it("should be case-insensitive for charset matching", async () => {
      const findings = await runCharsetCheck(
        "text/html; charset=UTF-8",
        `<html><head><meta charset="Utf-8"></head><body>Hi</body></html>`,
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
        path: "/",
      });

      const execution = await runCheck(unrecognizedCharsetCheck, [
        { request, response: undefined },
      ]);

      const findings =
        execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
      expect(findings).toHaveLength(0);
    });

    it("should include security guidance in description", async () => {
      const findings = await runCharsetCheck(
        "text/html; charset=foo-unknown",
        "<html><body>Hello</body></html>",
      );

      expect(findings[0].description).toContain("XSS");
      expect(findings[0].description).toContain("UTF-8");
    });
  });
});
