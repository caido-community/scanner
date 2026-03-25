import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import check from ".";

describe("aws-key-disclosure", () => {
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
          body: "AKIAIOSFODNN7EXAMPLE1",
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

  it("detects AKIA access key", async () => {
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
          body: "aws_key=AKIAIOSFODNN7EXAMPLE",
        }),
      },
    ]);
    expect(history).toHaveLength(1);
    expect(history[0]?.steps[0]?.findings).toHaveLength(1);
  });

  it("detects ASIA temporary access key", async () => {
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
          body: "temp_key=ASIA1234567890ABCDEF",
        }),
      },
    ]);
    expect(history).toHaveLength(1);
    expect(history[0]?.steps[0]?.findings).toHaveLength(1);
  });
});
