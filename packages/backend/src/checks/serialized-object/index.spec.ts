import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import serializedObjectCheck from "./index";

describe("Serialized Object in HTTP message", () => {
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
});
