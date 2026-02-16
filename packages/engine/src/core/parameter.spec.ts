import { describe, expect, it } from "vitest";

import { createMockRequest } from "../__tests__/mocks/request";

import { extractParameters } from "./parameter";

describe("extractParameters", () => {
  describe("query parameters", () => {
    it("should extract query parameters", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
        query: "foo=bar&baz=qux",
      });

      const parameters = extractParameters(request);

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

    it("should return empty array when no query string", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/page",
      });

      const parameters = extractParameters(request);

      expect(parameters).toEqual([]);
    });

    it("should handle URL encoded values", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/search",
        query: "q=hello%20world",
      });

      const parameters = extractParameters(request);

      expect(parameters[0]).toMatchObject({
        name: "q",
        value: "hello world",
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

      const parameters = extractParameters(request);

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

      const parameters = extractParameters(request);

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

      const parameters = extractParameters(request);

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
        body: JSON.stringify({ count: 42, active: true }),
      });

      const parameters = extractParameters(request);

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

      const parameters = extractParameters(request);

      expect(parameters).toEqual([]);
    });
  });

  describe("reflected filter", () => {
    it("should filter to only reflected parameters", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/search",
        query: "q=test&page=1",
      });

      const parameters = extractParameters(request, {
        reflected: true,
        responseBody: "Search results for: test",
      });

      expect(parameters).toHaveLength(1);
      expect(parameters[0]).toMatchObject({
        name: "q",
        value: "test",
        source: "query",
      });
    });

    it("should return all parameters when reflected is false", () => {
      const request = createMockRequest({
        id: "1",
        host: "example.com",
        method: "GET",
        path: "/search",
        query: "q=test&page=1",
      });

      const parameters = extractParameters(request, {
        reflected: false,
        responseBody: "Search results for: test",
      });

      expect(parameters).toHaveLength(2);
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

      const parameters = extractParameters(request);
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

      const parameters = extractParameters(request);
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

      const parameters = extractParameters(request);
      const spec = parameters[0]!.inject("attacker");

      expect(spec.getBody()?.toText()).toBe(
        JSON.stringify({ user: "attacker", role: "viewer" }),
      );
    });
  });
});
