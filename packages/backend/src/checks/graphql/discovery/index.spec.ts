import { createMockRequest, createMockResponse, runCheck } from "engine";
import { describe, expect, it } from "vitest";

import graphqlEndpointCheck from "./index";

describe("graphql-endpoint check", () => {
  it("should not run when response code is 500+", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/graphql",
    });

    const response = createMockResponse({
      id: "1",
      code: 500,
      headers: { "Content-Type": ["application/json"] },
      body: '{"errors": [{"message": "Internal error"}]}',
    });

    const executionHistory = await runCheck(graphqlEndpointCheck, [
      { request, response },
    ]);

    expect(executionHistory).toEqual([]);
  });

  it("should not run when no GraphQL indicators are present", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/api/users",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["application/json"] },
      body: '{"users": [{"id": 1, "name": "John"}]}',
    });

    const executionHistory = await runCheck(graphqlEndpointCheck, [
      { request, response },
    ]);

    expect(executionHistory).toEqual([]);
  });

  it("should detect GraphQL endpoint by path /graphql", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/graphql",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["application/json"] },
      body: '{"message": "Method not allowed"}',
    });

    const executionHistory = await runCheck(graphqlEndpointCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "graphql-endpoint",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "detect",
            findings: [
              {
                name: "GraphQL Endpoint Discovered",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect GraphQL endpoint by path /api/graphql", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/api/graphql",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["application/json"] },
      body: "{}",
    });

    const executionHistory = await runCheck(graphqlEndpointCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "graphql-endpoint",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "detect",
            findings: [
              {
                name: "GraphQL Endpoint Discovered",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect GraphQL endpoint by path /gql", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/gql",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["application/json"] },
      body: "{}",
    });

    const executionHistory = await runCheck(graphqlEndpointCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "graphql-endpoint",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "detect",
            findings: [
              {
                name: "GraphQL Endpoint Discovered",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect GraphQL endpoint by request body with operationName and query", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/api/v1/data",
      headers: { "Content-Type": ["application/json"] },
      body: '{"operationName":"GetUser","variables":{"id":"123"},"query":"query GetUser($id: ID!) { user(id: $id) { id name } }"}',
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["application/json"] },
      body: '{"data": {"user": {"id": "123", "name": "John"}}}',
    });

    const executionHistory = await runCheck(graphqlEndpointCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "graphql-endpoint",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "detect",
            findings: [
              {
                name: "GraphQL Endpoint Discovered",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should detect GraphQL endpoint by request body with query only", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/api/endpoint",
      headers: { "Content-Type": ["application/json"] },
      body: '{"query":"{ __typename }"}',
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["application/json"] },
      body: '{"data": {"__typename": "Query"}}',
    });

    const executionHistory = await runCheck(graphqlEndpointCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "graphql-endpoint",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "detect",
            findings: [
              {
                name: "GraphQL Endpoint Discovered",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should not detect GraphQL endpoint by response structure alone without GraphQL request", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/api/v1/query",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["application/json"] },
      body: '{"data": {"user": {"id": "1", "name": "John"}}}',
    });

    const executionHistory = await runCheck(graphqlEndpointCheck, [
      { request, response },
    ]);

    expect(executionHistory).toEqual([]);
  });

  it("should not detect GraphQL endpoint for OPTIONS requests", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "OPTIONS",
      path: "/graphql",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["application/json"] },
      body: "{}",
    });

    const executionHistory = await runCheck(graphqlEndpointCheck, [
      { request, response },
    ]);

    expect(executionHistory).toEqual([]);
  });

  it("should handle 400 responses on GraphQL paths", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/graphql",
    });

    const response = createMockResponse({
      id: "1",
      code: 400,
      headers: { "Content-Type": ["application/json"] },
      body: '{"errors": [{"message": "Query required"}]}',
    });

    const executionHistory = await runCheck(graphqlEndpointCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "graphql-endpoint",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "detect",
            findings: [
              {
                name: "GraphQL Endpoint Discovered",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });

  it("should handle null operationName in request body", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/api/endpoint",
      headers: { "Content-Type": ["application/json"] },
      body: '{"operationName":null,"query":"{ __typename }"}',
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["application/json"] },
      body: '{"data": {"__typename": "Query"}}',
    });

    const executionHistory = await runCheck(graphqlEndpointCheck, [
      { request, response },
    ]);

    expect(executionHistory).toMatchObject([
      {
        checkId: "graphql-endpoint",
        targetRequestId: "1",
        status: "completed",
        steps: [
          {
            stepName: "detect",
            findings: [
              {
                name: "GraphQL Endpoint Discovered",
                severity: "info",
              },
            ],
            result: "done",
          },
        ],
      },
    ]);
  });
});
