import { createMockRequest, createMockResponse, runChecks } from "engine";
import { describe, expect, it } from "vitest";

import graphqlEndpointCheck from "../discovery";

import graphqlContentTypeCheck from "./index";

const checks = [graphqlEndpointCheck, graphqlContentTypeCheck];

describe("graphql-content-type check", () => {
  it("should run after graphql-endpoint dependency", async () => {
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
        code: 415,
        headers: {},
        body: "Unsupported",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runChecks(checks, [{ request, response }], {
      sendHandler,
    });

    const endpointExecution = executionHistory.find(
      (e) => e.checkId === "graphql-endpoint",
    );
    const contentTypeExecution = executionHistory.find(
      (e) => e.checkId === "graphql-content-type",
    );

    expect(endpointExecution).toBeDefined();
    expect(contentTypeExecution).toBeDefined();
    expect(endpointExecution?.status).toBe("completed");
    expect(contentTypeExecution?.status).toBe("completed");
  });

  it("should find no issues when request already uses x-www-form-urlencoded", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/graphql",
      headers: { "Content-Type": ["application/x-www-form-urlencoded"] },
      body: '{"query": "{ __typename }"}',
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["application/json"] },
      body: '{"data": {"__typename": "Query"}}',
    });

    const executionHistory = await runChecks(checks, [{ request, response }]);

    const contentTypeExecution = executionHistory.find(
      (e) => e.checkId === "graphql-content-type",
    );
    expect(contentTypeExecution).toMatchObject({
      checkId: "graphql-content-type",
      targetRequestId: "1",
      status: "completed",
    });

    const findings =
      contentTypeExecution?.steps.flatMap((s) => s.findings) ?? [];
    expect(findings.length).toBe(0);
  });

  it("should detect vulnerability when endpoint accepts x-www-form-urlencoded", async () => {
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
        body: '{"data": {"__typename": "Query"}}',
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runChecks(checks, [{ request, response }], {
      sendHandler,
    });

    const contentTypeExecution = executionHistory.find(
      (e) => e.checkId === "graphql-content-type",
    );
    expect(contentTypeExecution).toMatchObject({
      checkId: "graphql-content-type",
      targetRequestId: "1",
      status: "completed",
    });

    const findings =
      contentTypeExecution?.steps.flatMap((s) => s.findings) ?? [];
    expect(findings.length).toBe(1);
    expect(findings[0]?.name).toBe(
      "GraphQL Content-Type Not Validated (application/x-www-form-urlencoded)",
    );
    expect(findings[0]?.severity).toBe("medium");
  });

  it("should find no issues when endpoint rejects non-JSON content types", async () => {
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
        code: 415,
        headers: { "Content-Type": ["application/json"] },
        body: '{"error": "Unsupported Media Type"}',
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runChecks(checks, [{ request, response }], {
      sendHandler,
    });

    const contentTypeExecution = executionHistory.find(
      (e) => e.checkId === "graphql-content-type",
    );
    const findings =
      contentTypeExecution?.steps.flatMap((s) => s.findings) ?? [];
    expect(findings.length).toBe(0);
  });

  it("should find no issues when response is not valid GraphQL", async () => {
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
        headers: { "Content-Type": ["text/html"] },
        body: "<html><body>Not a GraphQL response</body></html>",
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runChecks(checks, [{ request, response }], {
      sendHandler,
    });

    const contentTypeExecution = executionHistory.find(
      (e) => e.checkId === "graphql-content-type",
    );
    const findings =
      contentTypeExecution?.steps.flatMap((s) => s.findings) ?? [];
    expect(findings.length).toBe(0);
  });

  it("should not run when original body is empty (not a GraphQL request)", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/graphql",
      headers: { "Content-Type": ["application/json"] },
      body: "",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["application/json"] },
      body: '{"data": null}',
    });

    const executionHistory = await runChecks(checks, [{ request, response }]);

    const contentTypeExecution = executionHistory.find(
      (e) => e.checkId === "graphql-content-type",
    );
    const findings =
      contentTypeExecution?.steps.flatMap((s) => s.findings) ?? [];
    expect(findings.length).toBe(0);
  });

  it("should not run when request method is not POST", async () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/graphql",
      headers: { "Content-Type": ["application/json"] },
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "Content-Type": ["application/json"] },
      body: '{"data": {"user": {"id": "1"}}}',
    });

    const executionHistory = await runChecks(checks, [{ request, response }]);

    const contentTypeExecution = executionHistory.find(
      (e) => e.checkId === "graphql-content-type",
    );
    const findings =
      contentTypeExecution?.steps.flatMap((s) => s.findings) ?? [];
    expect(findings.length).toBe(0);
  });

  it("should find no issues when response only has errors (parsing failure)", async () => {
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
        body: '{"errors": [{"message": "Unexpected end of document", "locations": []}]}',
      });

      return Promise.resolve({ request: mockRequest, response: mockResponse });
    };

    const executionHistory = await runChecks(checks, [{ request, response }], {
      sendHandler,
    });

    const contentTypeExecution = executionHistory.find(
      (e) => e.checkId === "graphql-content-type",
    );
    const findings =
      contentTypeExecution?.steps.flatMap((s) => s.findings) ?? [];
    expect(findings.length).toBe(0);
  });
});
