import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import duplicateCookiesCheck from "./index";

const runDuplicateCookieCheck = async (
  setCookieHeaders: string[],
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
    headers: { "set-cookie": setCookieHeaders },
    body: "OK",
  });

  const execution = await runCheck(duplicateCookiesCheck, [
    { request, response },
  ]);

  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Duplicate cookies check", () => {
  describe("Detection", () => {
    it("should detect duplicate cookie names (case-insensitive)", async () => {
      const findings = await runDuplicateCookieCheck([
        "sessionId=abc123; Path=/; HttpOnly",
        "SessionID=def456; Path=/; Secure",
      ]);

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        name: "Duplicate cookies set",
        severity: "low",
      });
      expect(findings[0].description).toContain("sessionid");
      expect(findings[0].description).toContain("2 times");
    });

    it("should detect cookie set more than twice", async () => {
      const findings = await runDuplicateCookieCheck([
        "token=aaa",
        "Token=bbb",
        "TOKEN=ccc",
      ]);

      expect(findings).toHaveLength(1);
      expect(findings[0].description).toContain("token");
      expect(findings[0].description).toContain("3 times");
    });

    it("should detect multiple different cookies with duplicates", async () => {
      const findings = await runDuplicateCookieCheck([
        "session=a",
        "Session=b",
        "user=x",
        "User=y",
      ]);

      expect(findings).toHaveLength(1);
      expect(findings[0].description).toContain("session");
      expect(findings[0].description).toContain("user");
    });

    it("should report only duplicated cookies, not unique ones", async () => {
      const findings = await runDuplicateCookieCheck([
        "session=a",
        "session=b",
        "lang=en",
      ]);

      expect(findings).toHaveLength(1);
      expect(findings[0].description).toContain("session");
      expect(findings[0].description).not.toContain("lang");
    });
  });

  describe("False Positives", () => {
    it("should not flag unique cookie names", async () => {
      const findings = await runDuplicateCookieCheck([
        "sessionId=abc123",
        "lang=en",
        "theme=dark",
      ]);

      expect(findings).toHaveLength(0);
    });

    it("should not flag when no Set-Cookie headers present", async () => {
      const request = createMockRequest({
        id: "req",
        host: "example.com",
        method: "GET",
        path: "/",
      });

      const response = createMockResponse({
        id: "res",
        code: 200,
        headers: {},
        body: "OK",
      });

      const execution = await runCheck(duplicateCookiesCheck, [
        { request, response },
      ]);

      const findings =
        execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
      expect(findings).toHaveLength(0);
    });

    it("should not flag single cookie", async () => {
      const findings = await runDuplicateCookieCheck(["sessionId=abc123"]);
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

      const execution = await runCheck(duplicateCookiesCheck, [
        { request, response: undefined },
      ]);

      const findings =
        execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
      expect(findings).toHaveLength(0);
    });

    it("should include security guidance in description", async () => {
      const findings = await runDuplicateCookieCheck([
        "session=a",
        "session=b",
      ]);

      expect(findings[0].description).toContain("session fixation");
      expect(findings[0].description).toContain("inconsistent behaviour");
    });

    it("should normalize cookie names to lowercase", async () => {
      const findings = await runDuplicateCookieCheck([
        "SeSsIoN=a",
        "sEsSiOn=b",
      ]);

      expect(findings).toHaveLength(1);
      expect(findings[0].description).toMatch(/session.*2 times/i);
    });
  });
});
