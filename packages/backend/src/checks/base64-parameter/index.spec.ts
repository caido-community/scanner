import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import base64ParameterCheck from "./index";

const runBase64Check = async (config: {
  query?: string;
  body?: string;
}): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "req",
    host: "example.com",
    method: config.body ? "POST" : "GET",
    path: "/api",
    query: config.query,
    body: config.body,
    headers: { "Content-Type": ["application/x-www-form-urlencoded"] },
  });

  const response = createMockResponse({
    id: "res",
    code: 200,
    headers: { "content-type": ["text/plain"] },
    body: "OK",
  });

  const execution = await runCheck(base64ParameterCheck, [
    { request, response },
  ]);
  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("Base64 parameter check", () => {
  describe("Detection", () => {
    it("should detect base64 in query parameter", async () => {
      const findings = await runBase64Check({
        query: "token=YWJjZGVmZ2hpamtsbW5vcA==",
      });

      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        name: "Base64 encoded data in parameter",
        severity: "low",
      });
    });

    it("should detect base64 in body parameter", async () => {
      const findings = await runBase64Check({
        body: "data=SGVsbG9Xb3JsZEJhc2U2NA==",
      });

      expect(findings).toHaveLength(1);
      expect(findings[0].description).toContain("body");
    });

    it("should detect longer base64 strings", async () => {
      const findings = await runBase64Check({
        query: "val=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=",
      });

      expect(findings).toHaveLength(1);
    });

    it("should detect multiple base64 parameters", async () => {
      const findings = await runBase64Check({
        query:
          "tok1=YWJjZGVmZ2hpamtsbW5vcA==&tok2=MTIzNDU2Nzg5MGFiY2RlZg==",
      });

      expect(findings).toHaveLength(1);
      expect(findings[0].description).toContain("tok1");
      expect(findings[0].description).toContain("tok2");
    });
  });

  describe("False Positives", () => {
    it("should ignore short strings", async () => {
      const findings = await runBase64Check({ query: "token=YWJj" });
      expect(findings).toHaveLength(0);
    });

    it("should ignore non-base64 characters", async () => {
      const findings = await runBase64Check({
        query: "val=abcdefghijklmnop!@#$",
      });
      expect(findings).toHaveLength(0);
    });

    it("should ignore invalid base64 padding", async () => {
      const findings = await runBase64Check({
        query: "val=YWJjZGVmZ2hpamtsbW5vcA=",
      });
      expect(findings).toHaveLength(0);
    });

    it("should ignore non-multiple-of-4 length", async () => {
      const findings = await runBase64Check({ query: "val=YWJjZGVmZ2hpamtsbW5" });
      expect(findings).toHaveLength(0);
    });
  });

  describe("Edge Cases", () => {
    it("should include security guidance", async () => {
      const findings = await runBase64Check({
        query: "token=YWJjZGVmZ2hpamtsbW5vcA==",
      });

      expect(findings[0].description).toContain("sensitive information");
      expect(findings[0].description).toContain("encrypt");
    });
  });
});
