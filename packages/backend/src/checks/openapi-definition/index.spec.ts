import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import openApiCheck from "./index";

const runOpenApiCheck = async (body: string): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "req-openapi",
    host: "example.com",
    method: "GET",
    path: "/openapi.json",
    headers: { Host: ["example.com"] },
  });

  const response = createMockResponse({
    id: "res-openapi",
    code: 200,
    headers: { "content-type": ["application/json"] },
    body,
  });

  const execution = await runCheck(openApiCheck, [{ request, response }]);
  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("OpenAPI definition check", () => {
  it("detects JSON OpenAPI documents", async () => {
    const findings = await runOpenApiCheck(
      JSON.stringify({
        openapi: "3.0.1",
        info: { title: "API", version: "1.0" },
        paths: {},
      }),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "OpenAPI definition exposed",
      severity: "medium",
    });
  });

  it("detects YAML OpenAPI documents", async () => {
    const findings = await runOpenApiCheck(
      [
        "openapi: 3.0.2",
        "info:",
        "  title: API",
        "paths:",
        "  /users:",
        "    get:",
        "      responses:",
        "        '200':",
        "          description: OK",
      ].join("\n"),
    );

    expect(findings).toHaveLength(1);
  });

  it("does not flag unrelated JSON", async () => {
    const findings = await runOpenApiCheck(
      JSON.stringify({ message: "hello" }),
    );

    expect(findings).toHaveLength(0);
  });
});
