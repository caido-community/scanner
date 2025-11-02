import {
  createMockRequest,
  createMockResponse,
  runCheck,
  type SendHandler,
} from "engine";
import { describe, expect, it } from "vitest";

import refererCheck from "./index";

type HandlerConfig = {
  statusDifference?: boolean;
  bodyDelta?: number;
};

const buildSendHandler = (config: HandlerConfig = {}): SendHandler => {
  return (spec) => {
    const refererHeader = spec.getHeader("Referer");
    const refererValue = refererHeader?.[0] ?? "";

    const isExternal = refererValue.includes("attacker.example");
    const status = config.statusDifference === true && isExternal ? 403 : 200;

    let body = "consistent content";
    if (config.bodyDelta !== undefined && isExternal) {
      body = `consistent content${"x".repeat(config.bodyDelta)}`;
    }

    const mockRequest = createMockRequest({
      id: `req-${refererValue}`,
      host: spec.getHost(),
      method: spec.getMethod(),
      path: spec.getPath(),
      headers: spec.getHeaders(),
    });

    const mockResponse = createMockResponse({
      id: `res-${refererValue}`,
      code: status,
      headers: { "content-type": ["text/html"] },
      body,
    });

    return Promise.resolve({ request: mockRequest, response: mockResponse });
  };
};

const runRefererCheck = async (
  handlerConfig?: HandlerConfig,
): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "target-req",
    host: "example.com",
    method: "GET",
    path: "/",
    headers: { Host: ["example.com"] },
  });

  const response = createMockResponse({
    id: "target-res",
    code: 200,
    headers: { "content-type": ["text/html"] },
    body: "baseline content",
  });

  const execution = await runCheck(refererCheck, [{ request, response }], {
    sendHandler: buildSendHandler(handlerConfig),
  });

  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Referer dependent response check", () => {
  describe("Detection", () => {
    it("reports when status codes differ for external referer", async () => {
      const findings = await runRefererCheck({ statusDifference: true });

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        name: "Referer dependent response detected",
        severity: "medium",
      });
    });

    it("reports when body length differs significantly", async () => {
      const findings = await runRefererCheck({ bodyDelta: 150 });
      expect(findings).toHaveLength(1);
    });

    it("reports when both status and body differ", async () => {
      const findings = await runRefererCheck({
        statusDifference: true,
        bodyDelta: 150,
      });

      expect(findings).toHaveLength(1);
    });

    it("reports body difference at 101 byte threshold", async () => {
      const findings = await runRefererCheck({ bodyDelta: 101 });
      expect(findings).toHaveLength(1);
    });

    it("includes baseline and probe details in description", async () => {
      const findings = await runRefererCheck({ statusDifference: true });

      expect(findings[0].description).toContain("external");
      expect(findings[0].description).toContain("attacker.example");
      expect(findings[0].description).toContain("Baseline response");
    });
  });

  describe("False Positive Prevention", () => {
    it("does not report when responses are identical", async () => {
      const findings = await runRefererCheck();
      expect(findings).toHaveLength(0);
    });

    it("does not report when body length difference is within tolerance", async () => {
      const findings = await runRefererCheck({ bodyDelta: 80 });
      expect(findings).toHaveLength(0);
    });

    it("does not report at exactly 100 byte threshold", async () => {
      // baseline is "baseline content" (16 chars)
      // sendHandler uses "consistent content" (18 chars) + bodyDelta
      // delta = (18 + bodyDelta) - 16 = 2 + bodyDelta
      // For exactly 100 byte delta: 2 + 98 = 100
      const findings = await runRefererCheck({ bodyDelta: 98 });
      expect(findings).toHaveLength(0);
    });
  });

  describe("Edge Cases", () => {
    it("handles baseline response with no body", async () => {
      const request = createMockRequest({
        id: "target-req",
        host: "example.com",
        method: "GET",
        path: "/",
        headers: { Host: ["example.com"] },
      });

      const response = createMockResponse({
        id: "target-res",
        code: 200,
        headers: { "content-type": ["text/html"] },
        body: "",
      });

      const execution = await runCheck(refererCheck, [{ request, response }], {
        sendHandler: buildSendHandler({ bodyDelta: 150 }),
      });

      const findings =
        execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];

      expect(findings).toHaveLength(1);
    });

    it("includes security guidance about Referer risks", async () => {
      const findings = await runRefererCheck({ statusDifference: true });

      expect(findings[0].description).toContain("Referer");
      expect(findings[0].description).toContain("access control bypasses");
      expect(findings[0].description).toContain("consistent responses");
    });
  });
});
