import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import graphqlEndpointCheck from "./index";

const runEndpointCheck = async (body: string): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "req-graphql-endpoint",
    host: "example.com",
    method: "POST",
    path: "/graphql",
    headers: { Host: ["example.com"], "Content-Type": ["application/json"] },
  });

  const response = createMockResponse({
    id: "res-graphql-endpoint",
    code: 200,
    headers: { "content-type": ["application/json"] },
    body,
  });

  const execution = await runCheck(graphqlEndpointCheck, [
    { request, response },
  ]);
  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("GraphQL endpoint detected check", () => {
  it("detects GraphQL validation errors", async () => {
    const findings = await runEndpointCheck(
      JSON.stringify({
        errors: [
          {
            message: 'Cannot query field "uers" on type "Query".',
            extensions: { code: "GRAPHQL_VALIDATION_FAILED" },
          },
        ],
        data: null,
      }),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "GraphQL endpoint detected",
      severity: "info",
    });
  });

  it("detects GraphQL playground pages", async () => {
    const findings = await runEndpointCheck("<html>GraphQL Playground</html>");
    expect(findings).toHaveLength(1);
  });

  it("ignores non-GraphQL JSON", async () => {
    const findings = await runEndpointCheck(JSON.stringify({ message: "ok" }));
    expect(findings).toHaveLength(0);
  });
});
