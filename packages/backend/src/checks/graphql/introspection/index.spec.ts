import { createMockRequest, createMockResponse, runChecks } from "engine";
import { describe, expect, it } from "vitest";

import graphqlEndpointCheck from "../discovery";

import graphqlIntrospectionCheck from "./index";

const checks = [graphqlEndpointCheck, graphqlIntrospectionCheck];

describe("graphql-introspection check", () => {
  it("should not run when path does not contain graphql indicators", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/api/users",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: {},
      body: '{"users": []}',
    });

    const executionHistory = await runChecks(checks, [{ request, response }]);

    const introspectionExecution = executionHistory.find(
      (e) => e.checkId === "graphql-introspection",
    );

    const findings =
      introspectionExecution?.steps.flatMap((s) => s.findings) ?? [];
    expect(findings.length).toBe(0);
  });

  it("should detect introspection enabled via POST", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/graphql",
      headers: { "Content-Type": ["application/json"] },
      body: '{"query": "{ user { id } }"}',
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["application/json"] },
      body: '{"data": {"user": {"id": "1"}}}',
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "POST",
        path: "/graphql",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: { "Content-Type": ["application/json"] },
        body: JSON.stringify({
          data: {
            __schema: {
              types: [{ name: "Query" }, { name: "User" }, { name: "String" }],
            },
          },
        }),
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runChecks(checks, [{ request, response }], {
      sendHandler,
    });

    const introspectionExecution = executionHistory.find(
      (e) => e.checkId === "graphql-introspection",
    );

    expect(introspectionExecution).toBeDefined();
    const findings =
      introspectionExecution?.steps.flatMap((s) => s.findings) ?? [];
    expect(findings.length).toBe(1);
    expect(findings[0]).toMatchObject({
      name: "GraphQL Introspection Enabled",
      severity: "medium",
    });
  });

  it("should not detect when introspection is disabled", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/graphql",
      headers: { "Content-Type": ["application/json"] },
      body: '{"query": "{ user { id } }"}',
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["application/json"] },
      body: '{"data": {"user": {"id": "1"}}}',
    });

    const sendHandler = () => {
      const mockRequest = createMockRequest({
        id: "2",
        host: "example.com",
        method: "POST",
        path: "/graphql",
      });

      const mockResponse = createMockResponse({
        id: "2",
        code: 200,
        headers: { "Content-Type": ["application/json"] },
        body: JSON.stringify({
          errors: [
            {
              message:
                "GraphQL introspection is not allowed, but the query contained __schema or __type",
            },
          ],
        }),
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runChecks(checks, [{ request, response }], {
      sendHandler,
    });

    const introspectionExecution = executionHistory.find(
      (e) => e.checkId === "graphql-introspection",
    );

    const findings =
      introspectionExecution?.steps.flatMap((s) => s.findings) ?? [];
    expect(findings.length).toBe(0);
  });

  it("should detect introspection via GET when POST fails", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/graphql",
      headers: { "Content-Type": ["application/json"] },
      body: '{"query": "{ user { id } }"}',
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["application/json"] },
      body: '{"data": {"user": {"id": "1"}}}',
    });

    let callCount = 0;
    const sendHandler = () => {
      callCount += 1;

      const mockRequest = createMockRequest({
        id: String(callCount + 1),
        host: "example.com",
        method: callCount === 1 ? "POST" : "GET",
        path: "/graphql",
      });

      if (callCount === 1) {
        const mockResponse = createMockResponse({
          id: String(callCount + 1),
          code: 400,
          headers: {},
          body: '{"errors": [{"message": "Introspection not allowed"}]}',
        });
        return Promise.resolve({
          request: mockRequest,
          response: mockResponse,
        });
      }

      const mockResponse = createMockResponse({
        id: String(callCount + 1),
        code: 200,
        headers: { "Content-Type": ["application/json"] },
        body: JSON.stringify({
          data: {
            __schema: {
              types: [{ name: "Query" }, { name: "Mutation" }],
            },
          },
        }),
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runChecks(checks, [{ request, response }], {
      sendHandler,
    });

    const introspectionExecution = executionHistory.find(
      (e) => e.checkId === "graphql-introspection",
    );

    const findings =
      introspectionExecution?.steps.flatMap((s) => s.findings) ?? [];
    expect(findings.length).toBe(1);
    expect(findings[0]).toMatchObject({
      name: "GraphQL Introspection Enabled",
      severity: "medium",
    });
  });
});
