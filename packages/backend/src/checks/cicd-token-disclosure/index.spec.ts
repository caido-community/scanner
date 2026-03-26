import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import check from ".";

describe("cicd-token-disclosure", () => {
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
          code: 404,
          body: "bkua_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234",
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

  it("detects BuildKite token", async () => {
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
          body: "token=bkua_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234",
        }),
      },
    ]);
    expect(history).toHaveLength(1);
    expect(history[0]?.steps[0]?.findings).toHaveLength(1);
  });

  it("detects CircleCI token", async () => {
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
          body: 'circle_token: "abcdef1234567890abcdef1234567890abcdef12"',
        }),
      },
    ]);
    expect(history).toHaveLength(1);
    expect(history[0]?.steps[0]?.findings).toHaveLength(1);
  });

  it("detects CircleCI token case insensitive", async () => {
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
          body: "CIRCLE_TOKEN=abcdef1234567890abcdef1234567890abcdef12",
        }),
      },
    ]);
    expect(history).toHaveLength(1);
    expect(history[0]?.steps[0]?.findings).toHaveLength(1);
  });
});
