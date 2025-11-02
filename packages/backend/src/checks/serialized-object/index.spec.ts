import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import serializedObjectCheck from "./index";

describe("Serialized Object in HTTP message", () => {
  describe("Detection - Requests", () => {
    it("detects serialized object signature in request body", async () => {
      const request = createMockRequest({
        id: "req-1",
        host: "example.com",
        method: "POST",
        path: "/submit",
        headers: {
          "content-type": ["application/octet-stream"],
        },
        body: "rO0ABXNyABFqYXZhLnV0aWwuRGF0Zc8ZksnCn0wCAAFMAAZjYWxlbmRhcgAAeHIAPm9yZy5qc29uLmJvbnguSmF2YV91dGlsX0Zha2VfU2VyaWFsaXphYmxlQ2xhc3MT6FawuQCObAIAAHhyABFqYXZhLnV0aWwuQ2FsZW5kYXJFeGFtcGxl",
      });

      const response = createMockResponse({
        id: "res-1",
        code: 200,
        headers: { "content-type": ["text/plain"] },
        body: "OK",
      });

      const executionHistory = await runCheck(serializedObjectCheck, [
        { request, response },
      ]);

      expect(executionHistory).toMatchObject([
        {
          checkId: "serialized-object-http-message",
          steps: [
            {
              findings: [
                {
                  name: "Serialized object detected in HTTP request",
                  severity: "high",
                },
              ],
            },
          ],
        },
      ]);
    });

    it("detects serialized object via request content-type header", async () => {
      const request = createMockRequest({
        id: "req-ct",
        host: "example.com",
        method: "POST",
        path: "/upload",
        headers: {
          "content-type": ["application/x-java-serialized-object"],
        },
        body: "some-data",
      });

      const response = createMockResponse({
        id: "res-ct",
        code: 200,
        headers: { "content-type": ["text/plain"] },
        body: "OK",
      });

      const executionHistory = await runCheck(serializedObjectCheck, [
        { request, response },
      ]);

      expect(executionHistory[0].steps[0].findings).toHaveLength(1);
      expect(executionHistory[0].steps[0].findings[0].severity).toBe("high");
    });

    it("detects serialized content-type with charset parameter", async () => {
      const request = createMockRequest({
        id: "req-charset",
        host: "example.com",
        method: "POST",
        path: "/upload",
        headers: {
          "content-type": [
            "application/x-java-serialized-object;charset=UTF-8",
          ],
        },
        body: "data",
      });

      const response = createMockResponse({
        id: "res-charset",
        code: 200,
        headers: { "content-type": ["text/plain"] },
        body: "OK",
      });

      const executionHistory = await runCheck(serializedObjectCheck, [
        { request, response },
      ]);

      expect(executionHistory[0].steps[0].findings).toHaveLength(1);
    });

    it("includes RCE warning in request finding description", async () => {
      const request = createMockRequest({
        id: "req-desc",
        host: "example.com",
        method: "POST",
        path: "/api",
        body: "rO0ABtest",
      });

      const response = createMockResponse({
        id: "res-desc",
        code: 200,
        headers: {},
        body: "OK",
      });

      const executionHistory = await runCheck(serializedObjectCheck, [
        { request, response },
      ]);

      expect(executionHistory[0].steps[0].findings[0].description).toContain(
        "remote code execution",
      );
      expect(executionHistory[0].steps[0].findings[0].description).toContain(
        "deserialization",
      );
    });
  });

  describe("Detection - Responses", () => {
    it("detects serialized object via response content-type", async () => {
      const request = createMockRequest({
        id: "req-2",
        host: "example.com",
        method: "GET",
        path: "/download",
      });

      const response = createMockResponse({
        id: "res-2",
        code: 200,
        headers: {
          "content-type": ["application/x-java-serialized-object"],
        },
        body: "binary-content",
      });

      const executionHistory = await runCheck(serializedObjectCheck, [
        { request, response },
      ]);

      expect(executionHistory).toMatchObject([
        {
          steps: [
            {
              findings: [
                {
                  name: "Serialized object detected in HTTP response",
                  severity: "medium",
                },
              ],
            },
          ],
        },
      ]);
    });

    it("detects serialized object signature in response body", async () => {
      const request = createMockRequest({
        id: "req-3",
        host: "example.com",
        method: "GET",
        path: "/data",
      });

      const response = createMockResponse({
        id: "res-3",
        code: 200,
        headers: {
          "content-type": ["application/octet-stream"],
        },
        body: "aced0005737200176a6176612e7574696c2e566563746f72000000000000014e",
      });

      const executionHistory = await runCheck(serializedObjectCheck, [
        { request, response },
      ]);

      expect(executionHistory).toMatchObject([
        {
          steps: [
            {
              findings: [
                {
                  name: "Serialized object detected in HTTP response",
                },
              ],
            },
          ],
        },
      ]);
    });

    it("detects both request and response serialization", async () => {
      const request = createMockRequest({
        id: "req-both",
        host: "example.com",
        method: "POST",
        path: "/api",
        body: "rO0ABdata",
      });

      const response = createMockResponse({
        id: "res-both",
        code: 200,
        headers: {
          "content-type": ["application/x-java-serialized-object"],
        },
        body: "response-data",
      });

      const executionHistory = await runCheck(serializedObjectCheck, [
        { request, response },
      ]);

      expect(executionHistory[0].steps[0].findings).toHaveLength(2);
      expect(executionHistory[0].steps[0].findings[0].name).toContain(
        "request",
      );
      expect(executionHistory[0].steps[0].findings[1].name).toContain(
        "response",
      );
    });
  });

  describe("False Positive Prevention", () => {
    it("does not report when no indicators are present", async () => {
      const request = createMockRequest({
        id: "req-4",
        host: "example.com",
        method: "POST",
        path: "/submit",
        headers: {
          "content-type": ["application/json"],
        },
        body: '{"key":"value"}',
      });

      const response = createMockResponse({
        id: "res-4",
        code: 200,
        headers: {
          "content-type": ["application/json"],
        },
        body: '{"status":"ok"}',
      });

      const executionHistory = await runCheck(serializedObjectCheck, [
        { request, response },
      ]);

      expect(executionHistory).toMatchObject([
        {
          steps: [
            {
              findings: [],
              result: "done",
            },
          ],
        },
      ]);
    });

    it("does not report for plain text without signatures", async () => {
      const request = createMockRequest({
        id: "req-text",
        host: "example.com",
        method: "POST",
        path: "/api",
        body: "This is just regular text content",
      });

      const response = createMockResponse({
        id: "res-text",
        code: 200,
        headers: { "content-type": ["text/plain"] },
        body: "Response text",
      });

      const executionHistory = await runCheck(serializedObjectCheck, [
        { request, response },
      ]);

      expect(executionHistory[0].steps[0].findings).toHaveLength(0);
    });
  });

  describe("Edge Cases", () => {
    it("handles empty request body", async () => {
      const request = createMockRequest({
        id: "req-empty",
        host: "example.com",
        method: "POST",
        path: "/api",
        body: "",
      });

      const response = createMockResponse({
        id: "res-empty",
        code: 200,
        headers: {},
        body: "OK",
      });

      const executionHistory = await runCheck(serializedObjectCheck, [
        { request, response },
      ]);

      expect(executionHistory[0].steps[0].findings).toHaveLength(0);
    });
  });
});
