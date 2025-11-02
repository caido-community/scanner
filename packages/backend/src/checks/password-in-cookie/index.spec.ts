import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import passwordCookieCheck from "./index";

const runPasswordCookieCheck = async (
  setCookieHeaders: string[],
): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "req-cookie",
    host: "example.com",
    method: "GET",
    path: "/",
    headers: { Host: ["example.com"] },
  });

  const response = createMockResponse({
    id: "res-cookie",
    code: 200,
    headers: { "set-cookie": setCookieHeaders },
    body: "",
  });

  const execution = await runCheck(passwordCookieCheck, [
    { request, response },
  ]);

  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Password value stored in cookie check", () => {
  describe("Detection", () => {
    it("flags cookies whose name indicates a password", async () => {
      const findings = await runPasswordCookieCheck([
        "password=SuperSecret123; Path=/; HttpOnly",
      ]);

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        name: "Password value stored in cookie",
        severity: "high",
      });
    });

    it("flags cookies whose value indicates a password", async () => {
      const findings = await runPasswordCookieCheck([
        "auth=Pwd%3DPlainText; Path=/; HttpOnly",
      ]);

      expect(findings).toHaveLength(1);
    });

    it("detects passwd keyword in cookie name", async () => {
      const findings = await runPasswordCookieCheck([
        "user_passwd=hashed123; Path=/",
      ]);

      expect(findings).toHaveLength(1);
    });

    it("detects pwd keyword in cookie name", async () => {
      const findings = await runPasswordCookieCheck([
        "usrpwd=secret; Path=/; Secure",
      ]);

      expect(findings).toHaveLength(1);
    });

    it("detects passcode keyword in cookie name", async () => {
      const findings = await runPasswordCookieCheck([
        "access-passcode=1234; Path=/",
      ]);

      expect(findings).toHaveLength(1);
    });

    it("detects password keywords with separators", async () => {
      const findings = await runPasswordCookieCheck([
        "user-password=value1; Path=/",
        "user_pwd=value2; Path=/",
        "user.passwd=value3; Path=/",
      ]);

      expect(findings).toHaveLength(1);
      expect(findings[0].description).toContain("user-password");
      expect(findings[0].description).toContain("user_pwd");
      expect(findings[0].description).toContain("user.passwd");
    });

    it("detects password keyword in brackets", async () => {
      const findings = await runPasswordCookieCheck([
        "data[password]=secret; Path=/",
      ]);

      expect(findings).toHaveLength(1);
    });
  });

  describe("False Positive Prevention", () => {
    it("does not flag unrelated cookies", async () => {
      const findings = await runPasswordCookieCheck([
        "sessionid=abcdef123456; Path=/; HttpOnly; Secure",
      ]);

      expect(findings).toHaveLength(0);
    });

    it("does not flag bypass keyword", async () => {
      const findings = await runPasswordCookieCheck([
        "can_bypass=true; Path=/",
      ]);

      expect(findings).toHaveLength(0);
    });

    it("does not flag passport keyword", async () => {
      const findings = await runPasswordCookieCheck([
        "passport_session=abc123; Path=/",
      ]);

      expect(findings).toHaveLength(0);
    });
  });

  describe("Edge Cases", () => {
    it("handles empty password cookie value", async () => {
      const findings = await runPasswordCookieCheck(["password=; Path=/"]);

      expect(findings).toHaveLength(1);
      expect(findings[0].description).toContain("empty value");
    });

    it("includes security flags in description", async () => {
      const findings = await runPasswordCookieCheck([
        "pwd=secret; Path=/; HttpOnly; Secure",
      ]);

      expect(findings).toHaveLength(1);
      expect(findings[0].description).toContain("HttpOnly");
      expect(findings[0].description).toContain("Secure");
    });

    it("returns no findings when no cookies are set", async () => {
      const findings = await runPasswordCookieCheck([]);

      expect(findings).toHaveLength(0);
    });
  });
});
