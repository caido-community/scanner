import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import cookieParentDomainCheck from "./index";

const runParentDomainCheck = async (
  host: string,
  setCookieHeaders: string[],
): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "req",
    host,
    method: "GET",
    path: "/",
  });

  const response = createMockResponse({
    id: "res",
    code: 200,
    headers: { "set-cookie": setCookieHeaders },
    body: "OK",
  });

  const execution = await runCheck(cookieParentDomainCheck, [
    { request, response },
  ]);

  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Cookie parent domain check", () => {
  describe("Detection", () => {
    it("should flag cookies scoped to parent domain", async () => {
      const findings = await runParentDomainCheck("app.example.com", [
        "sessionId=abc123; Domain=.example.com; Path=/",
      ]);

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        name: "Cookie scoped to parent domain",
        severity: "medium",
      });
    });

    it("should flag cookies with parent domain without leading dot", async () => {
      const findings = await runParentDomainCheck("sub.example.com", [
        "token=xyz; Domain=example.com",
      ]);

      expect(findings).toHaveLength(1);
    });

    it("should detect multiple cookies with parent domain issues", async () => {
      const findings = await runParentDomainCheck("app.example.com", [
        "session=abc; Domain=.example.com",
        "token=xyz; Domain=example.com",
      ]);

      expect(findings).toHaveLength(1);
      expect(findings[0].description).toContain("session");
      expect(findings[0].description).toContain("token");
    });

    it("should be case-insensitive for domain matching", async () => {
      const findings = await runParentDomainCheck("App.Example.COM", [
        "id=123; Domain=.EXAMPLE.com",
      ]);

      expect(findings).toHaveLength(1);
    });
  });

  describe("False Positives", () => {
    it("should not flag cookie scoped to exact host", async () => {
      const findings = await runParentDomainCheck("app.example.com", [
        "sessionId=abc123; Domain=app.example.com; Path=/",
      ]);

      expect(findings).toHaveLength(0);
    });

    it("should not flag cookies without Domain attribute", async () => {
      const findings = await runParentDomainCheck("app.example.com", [
        "session=abc; Path=/; Secure",
      ]);

      expect(findings).toHaveLength(0);
    });

    it("should not flag when no Set-Cookie headers present", async () => {
      const request = createMockRequest({
        id: "req",
        host: "app.example.com",
        method: "GET",
        path: "/",
      });

      const response = createMockResponse({
        id: "res",
        code: 200,
        headers: {},
        body: "OK",
      });

      const execution = await runCheck(cookieParentDomainCheck, [
        { request, response },
      ]);

      const findings =
        execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
      expect(findings).toHaveLength(0);
    });

    it("should not flag sibling or unrelated domains", async () => {
      const findings = await runParentDomainCheck("app.example.com", [
        "session=abc; Domain=other.example.com",
      ]);

      expect(findings).toHaveLength(0);
    });
  });

  describe("Edge Cases", () => {
    it("should not run when response is missing", async () => {
      const request = createMockRequest({
        id: "req",
        host: "app.example.com",
        method: "GET",
        path: "/",
      });

      const execution = await runCheck(cookieParentDomainCheck, [
        { request, response: undefined },
      ]);

      const findings =
        execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
      expect(findings).toHaveLength(0);
    });

    it("should include security guidance in description", async () => {
      const findings = await runParentDomainCheck("app.example.com", [
        "session=abc; Domain=.example.com",
      ]);

      expect(findings[0].description).toContain("parent domain");
      expect(findings[0].description).toContain("session fixation");
      expect(findings[0].description).toContain("sibling subdomains");
    });

    it("should flag only risky cookies in mixed scenarios", async () => {
      const findings = await runParentDomainCheck("app.example.com", [
        "safe=123; Domain=app.example.com",
        "risky=456; Domain=.example.com",
      ]);

      expect(findings).toHaveLength(1);
      expect(findings[0].description).toContain("risky");
      expect(findings[0].description).not.toContain("safe");
    });
  });
});
