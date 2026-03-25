import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import check from ".";

describe("gcp-key-disclosure", () => {
  it("does not run on non-200 response", async () => {
    const history = await runCheck(check, [
      {
        request: createMockRequest({
          id: "1",
          host: "example.com",
          method: "GET",
          path: "/",
        }),
        response: createMockResponse({
          id: "1",
          code: 500,
          body: "AIzaSyA1234567890abcdefghijklmnopqrstuv",
        }),
      },
    ]);
    expect(history).toHaveLength(0);
  });

  it("finds nothing on clean response", async () => {
    const history = await runCheck(check, [
      {
        request: createMockRequest({
          id: "1",
          host: "example.com",
          method: "GET",
          path: "/",
        }),
        response: createMockResponse({
          id: "1",
          code: 200,
          body: "normal content without secrets",
        }),
      },
    ]);
    expect(history).toHaveLength(1);
    expect(history[0]?.steps[0]?.findings).toHaveLength(0);
  });

  it("detects GCP API key", async () => {
    const history = await runCheck(check, [
      {
        request: createMockRequest({
          id: "1",
          host: "example.com",
          method: "GET",
          path: "/",
        }),
        response: createMockResponse({
          id: "1",
          code: 200,
          body: "key=AIzaSyA1234567890abcdefghijklmnopqrstuv",
        }),
      },
    ]);
    expect(history).toHaveLength(1);
    expect(history[0]?.steps[0]?.findings).toHaveLength(1);
  });

  it("detects service account JSON", async () => {
    const history = await runCheck(check, [
      {
        request: createMockRequest({
          id: "1",
          host: "example.com",
          method: "GET",
          path: "/",
        }),
        response: createMockResponse({
          id: "1",
          code: 200,
          body: '{"type" : "service_account", "project_id": "my-project"}',
        }),
      },
    ]);
    expect(history).toHaveLength(1);
    expect(history[0]?.steps[0]?.findings).toHaveLength(1);
  });
});
