import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import graphqlSuggestionsCheck from "./index";

const executeCheck = async (body: string): Promise<unknown[]> => {
  const request = createMockRequest({
    id: "req-graphql-suggestions",
    host: "example.com",
    method: "POST",
    path: "/graphql",
    headers: { Host: ["example.com"], "Content-Type": ["application/json"] },
  });

  const response = createMockResponse({
    id: "res-graphql-suggestions",
    code: 400,
    headers: { "content-type": ["application/json"] },
    body,
  });

  const execution = await runCheck(graphqlSuggestionsCheck, [
    { request, response },
  ]);

  return execution[0]?.steps[execution[0].steps.length - 1]?.findings ?? [];
};

describe("GraphQL suggestions enabled check", () => {
  it("detects suggestion messages", async () => {
    const findings = await executeCheck(
      JSON.stringify({
        errors: [
          {
            message:
              'Cannot query field "uers" on type "Query". Did you mean "users"?',
          },
        ],
      }),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "GraphQL suggestions enabled",
      severity: "low",
    });
  });

  it("detects didYouMean extensions", async () => {
    const findings = await executeCheck(
      JSON.stringify({
        errors: [
          {
            message: 'Cannot query field "uers" on type "Query".',
            extensions: { didYouMean: ["users"] },
          },
        ],
      }),
    );

    expect(findings).toHaveLength(1);
  });

  it("ignores responses without suggestions", async () => {
    const findings = await executeCheck(JSON.stringify({ errors: [] }));
    expect(findings).toHaveLength(0);
  });
});
