import { createMockRequest, createMockResponse } from "engine";
import { describe, expect, it } from "vitest";

import {
  extractParameters,
  extractReflectedParameters,
  hasParameters,
} from "./parameters";

const createContext = (
  request: ReturnType<typeof createMockRequest>,
  response?: ReturnType<typeof createMockResponse>,
) => ({
  target: { request, response },
  sdk: {} as never,
  runtime: {} as never,
  config: {} as never,
});

describe("extractParameters", () => {
  describe("query parameters", () => {
    it("should extract query parameters with values", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "foo=bar&baz=qux",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toHaveLength(2);
      expect(parameters[0]).toMatchObject({
        name: "foo",
        value: "bar",
        source: "query",
      });
      expect(parameters[1]).toMatchObject({
        name: "baz",
        value: "qux",
        source: "query",
      });
    });

    it("should extract parameters with empty values", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "ble=&test=2",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toHaveLength(2);
      expect(parameters[0]).toMatchObject({
        name: "ble",
        value: "",
        source: "query",
      });
      expect(parameters[1]).toMatchObject({
        name: "test",
        value: "2",
        source: "query",
      });
    });

    it("should return empty array when no query string", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toEqual([]);
    });

    it("should handle URL encoded values", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "param=hello%20world&special=%3Cscript%3E",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters[0]).toMatchObject({
        name: "param",
        value: "hello world",
        source: "query",
      });
      expect(parameters[1]).toMatchObject({
        name: "special",
        value: "<script>",
        source: "query",
      });
    });
  });

  describe("body parameters (form)", () => {
    it("should extract form body parameters", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/submit",
        headers: { "Content-Type": ["application/x-www-form-urlencoded"] },
        body: "username=admin&password=secret",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toHaveLength(2);
      expect(parameters[0]).toMatchObject({
        name: "username",
        value: "admin",
        source: "body",
      });
      expect(parameters[1]).toMatchObject({
        name: "password",
        value: "secret",
        source: "body",
      });
    });

    it("should not extract body parameters for GET requests", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        headers: { "Content-Type": ["application/x-www-form-urlencoded"] },
        body: "foo=bar",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toEqual([]);
    });
  });

  describe("body parameters (JSON)", () => {
    it("should extract JSON body parameters", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/api",
        headers: { "Content-Type": ["application/json"] },
        body: JSON.stringify({ user: "admin", role: "viewer" }),
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toHaveLength(2);
      expect(parameters[0]).toMatchObject({
        name: "user",
        value: "admin",
        source: "body",
      });
      expect(parameters[1]).toMatchObject({
        name: "role",
        value: "viewer",
        source: "body",
      });
    });

    it("should stringify non-string JSON values", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/api",
        headers: { "Content-Type": ["application/json"] },
        body: JSON.stringify({
          count: 42,
          active: true,
          items: [1, 2, 3],
          meta: { x: "y" },
        }),
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toHaveLength(4);
      expect(parameters[0]).toMatchObject({
        name: "count",
        value: "42",
        source: "body",
      });
      expect(parameters[1]).toMatchObject({
        name: "active",
        value: "true",
        source: "body",
      });
      expect(parameters[2]).toMatchObject({
        name: "items",
        value: "[1,2,3]",
        source: "body",
      });
      expect(parameters[3]).toMatchObject({
        name: "meta",
        value: '{"x":"y"}',
        source: "body",
      });
    });

    it("should handle invalid JSON gracefully", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/api",
        headers: { "Content-Type": ["application/json"] },
        body: "not valid json",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toEqual([]);
    });
  });

  describe("combined parameters", () => {
    it("should extract both query and body parameters", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/submit",
        query: "action=update",
        headers: { "Content-Type": ["application/x-www-form-urlencoded"] },
        body: "data=value",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);

      expect(parameters).toHaveLength(2);
      expect(parameters[0]).toMatchObject({
        name: "action",
        value: "update",
        source: "query",
      });
      expect(parameters[1]).toMatchObject({
        name: "data",
        value: "value",
        source: "body",
      });
    });
  });

  describe("inject", () => {
    it("should inject into query parameter", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "foo=bar&baz=qux",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);
      const spec = parameters[0]!.inject("INJECTED");

      expect(spec.getQuery()).toBe("foo=INJECTED&baz=qux");
    });

    it("should inject into form body parameter", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/submit",
        headers: { "Content-Type": ["application/x-www-form-urlencoded"] },
        body: "username=admin&password=secret",
      });

      const context = createContext(request);
      const parameters = extractParameters(context);
      const spec = parameters[0]!.inject("attacker");

      expect(spec.getBody()?.toText()).toBe(
        "username=attacker&password=secret",
      );
    });

    it("should inject into JSON body parameter", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "POST",
        path: "/api",
        headers: { "Content-Type": ["application/json"] },
        body: JSON.stringify({ user: "admin", role: "viewer" }),
      });

      const context = createContext(request);
      const parameters = extractParameters(context);
      const spec = parameters[0]!.inject("attacker");

      expect(spec.getBody()?.toText()).toBe(
        JSON.stringify({ user: "attacker", role: "viewer" }),
      );
    });
  });
});

describe("extractReflectedParameters", () => {
  it("should return parameters that are reflected in response", () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/search",
      query: "q=test&page=1",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: {},
      body: "Search results for: test",
    });

    const context = createContext(request, response);
    const parameters = extractReflectedParameters(context);

    expect(parameters).toHaveLength(1);
    expect(parameters[0]).toMatchObject({
      name: "q",
      value: "test",
      source: "query",
    });
  });

  it("should return empty array when no parameters are reflected", () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/search",
      query: "q=secretvalue",
    });

    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: {},
      body: "No results found",
    });

    const context = createContext(request, response);
    const parameters = extractReflectedParameters(context);

    expect(parameters).toEqual([]);
  });

  it("should return all parameters when response is undefined", () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/search",
      query: "q=test&page=1",
    });

    const context = createContext(request, undefined);
    const parameters = extractReflectedParameters(context);

    expect(parameters).toHaveLength(2);
    expect(parameters[0]).toMatchObject({
      name: "q",
      value: "test",
      source: "query",
    });
    expect(parameters[1]).toMatchObject({
      name: "page",
      value: "1",
      source: "query",
    });
  });
});

describe("hasParameters", () => {
  it("should return true when request has query parameters", () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page",
      query: "foo=bar",
    });

    expect(hasParameters({ request, response: undefined })).toBe(true);
  });

  it("should return true when request has body", () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "POST",
      path: "/submit",
      body: "data=value",
    });

    expect(hasParameters({ request, response: undefined })).toBe(true);
  });

  it("should return false when request has no parameters or body", () => {
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/page",
      query: "",
    });

    expect(hasParameters({ request, response: undefined })).toBe(false);
  });
});
