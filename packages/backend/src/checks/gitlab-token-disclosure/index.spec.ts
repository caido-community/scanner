import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import check from ".";

describe("gitlab-token-disclosure", () => {
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
          body: "glpat-ABCDEFGHIJklmnopqrstuv",
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

  it("detects glpat personal access token", async () => {
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
          body: "token=glpat-ABCDEFGHIJklmnopqrstuv",
        }),
      },
    ]);
    expect(history).toHaveLength(1);
    expect(history[0]?.steps[0]?.findings).toHaveLength(1);
  });

  it("detects glptt pipeline trigger token", async () => {
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
          body: "trigger=glptt-ABCDEFGHIJklmnopqrstuv",
        }),
      },
    ]);
    expect(history).toHaveLength(1);
    expect(history[0]?.steps[0]?.findings).toHaveLength(1);
  });

  it("detects glrt runner registration token", async () => {
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
          body: "runner=glrt-ABCDEFGHIJklmnopqrstuv",
        }),
      },
    ]);
    expect(history).toHaveLength(1);
    expect(history[0]?.steps[0]?.findings).toHaveLength(1);
  });
});
