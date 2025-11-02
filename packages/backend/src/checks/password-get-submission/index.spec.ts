import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import passwordGetCheck from "./index";

const buildTarget = (config: {
  method: string;
  path?: string;
  query?: string;
}): {
  request: ReturnType<typeof createMockRequest>;
  response: ReturnType<typeof createMockResponse>;
} => {
  const request = createMockRequest({
    id: `req-${config.method.toLowerCase()}`,
    host: "example.com",
    method: config.method,
    path: config.path ?? "/login",
    query: config.query,
    headers: { Host: ["example.com"] },
  });

  const response = createMockResponse({
    id: `res-${config.method.toLowerCase()}`,
    code: 200,
    headers: { "content-type": ["text/html"] },
    body: "<html></html>",
  });

  return { request, response };
};

const extractFindings = async (
  target: ReturnType<typeof buildTarget>,
): Promise<unknown[]> => {
  const execution = await runCheck(passwordGetCheck, [target]);
  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Password submitted using GET method check", () => {
  describe("Detection", () => {
    it("flags GET requests with password query parameter", async () => {
      const target = buildTarget({
        method: "GET",
        query: "username=user&password=secret123",
      });

      const findings = await extractFindings(target);
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        severity: "high",
        name: "Password submitted using GET method",
      });
    });

    it("flags GET requests with derived password parameter names", async () => {
      const target = buildTarget({
        method: "GET",
        query: "userPassword=s3cr3t",
      });

      const findings = await extractFindings(target);
      expect(findings).toHaveLength(1);
    });

    it("detects passwd keyword in parameter name", async () => {
      const target = buildTarget({
        method: "GET",
        query: "user_passwd=hunter2",
      });

      const findings = await extractFindings(target);
      expect(findings).toHaveLength(1);
    });

    it("detects pwd keyword in parameter name", async () => {
      const target = buildTarget({
        method: "GET",
        query: "usrpwd=secret",
      });

      const findings = await extractFindings(target);
      expect(findings).toHaveLength(1);
    });

    it("detects passcode keyword in parameter name", async () => {
      const target = buildTarget({
        method: "GET",
        query: "login-passcode=1234",
      });

      const findings = await extractFindings(target);
      expect(findings).toHaveLength(1);
    });

    it("detects password keywords with separators", async () => {
      const target = buildTarget({
        method: "GET",
        query: "user-password=val1&user_pwd=val2",
      });

      const findings = await extractFindings(target);
      expect(findings).toHaveLength(1);
      expect(findings[0].description).toContain("user-password");
      expect(findings[0].description).toContain("user_pwd");
    });

    it("detects password keyword in brackets", async () => {
      const target = buildTarget({
        method: "GET",
        query: "data[password]=secret",
      });

      const findings = await extractFindings(target);
      expect(findings).toHaveLength(1);
    });
  });

  describe("False Positive Prevention", () => {
    it("does not flag when password-like parameters are absent", async () => {
      const target = buildTarget({
        method: "GET",
        query: "username=user&token=abc",
      });

      const findings = await extractFindings(target);
      expect(findings).toHaveLength(0);
    });

    it("does not flag non-GET requests", async () => {
      const target = buildTarget({
        method: "POST",
        query: "password=secret",
      });

      const findings = await extractFindings(target);
      expect(findings).toHaveLength(0);
    });

    it("does not flag PUT requests with password parameters", async () => {
      const target = buildTarget({
        method: "PUT",
        query: "password=secret",
      });

      const findings = await extractFindings(target);
      expect(findings).toHaveLength(0);
    });

    it("does not flag bypass or passport keywords", async () => {
      const target = buildTarget({
        method: "GET",
        query: "bypass=1&passport_id=ABC123",
      });

      const findings = await extractFindings(target);
      expect(findings).toHaveLength(0);
    });
  });

  describe("Edge Cases", () => {
    it("handles empty password parameter value", async () => {
      const target = buildTarget({
        method: "GET",
        query: "password=",
      });

      const findings = await extractFindings(target);
      expect(findings).toHaveLength(1);
      expect(findings[0].description).toContain("empty value");
    });

    it("handles GET requests with no query string", async () => {
      const target = buildTarget({
        method: "GET",
        query: undefined,
      });

      const findings = await extractFindings(target);
      expect(findings).toHaveLength(0);
    });

    it("includes security guidance about POST and HTTPS", async () => {
      const target = buildTarget({
        method: "GET",
        query: "password=secret",
      });

      const findings = await extractFindings(target);
      expect(findings[0].description).toContain("POST-based submission");
      expect(findings[0].description).toContain("HTTPS");
      expect(findings[0].description).toContain("browser history");
    });
  });
});
