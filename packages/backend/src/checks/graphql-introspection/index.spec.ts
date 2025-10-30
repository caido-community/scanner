import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import graphqlIntrospectionCheck from "./index";

const executeCheck = async (body: string): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "req-graphql",
    host: "example.com",
    method: "POST",
    path: "/graphql",
    headers: { Host: ["example.com"], "Content-Type": ["application/json"] },
  });

  const response = createMockResponse({
    id: "res-graphql",
    code: 200,
    headers: { "content-type": ["application/json"] },
    body,
  });

  const execution = await runCheck(graphqlIntrospectionCheck, [
    { request, response },
  ]);

  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("GraphQL introspection check", () => {
  it("detects __schema introspection responses", async () => {
    const findings = await executeCheck(
      JSON.stringify({
        data: {
          __schema: {
            queryType: { name: "Query" },
          },
        },
      }),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "GraphQL introspection enabled",
      severity: "medium",
    });
  });

  it("detects __type introspection responses", async () => {
    const findings = await executeCheck(
      JSON.stringify({
        data: {
          __type: {
            name: "User",
          },
        },
      }),
    );

    expect(findings).toHaveLength(1);
  });

  it("ignores non-introspection responses", async () => {
    const findings = await executeCheck(
      JSON.stringify({ data: { users: [] } }),
    );

    expect(findings).toHaveLength(0);
  });
});
