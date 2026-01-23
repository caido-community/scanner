import { createMockRequest, createMockResponse } from "engine";
import { describe, expect, it } from "vitest";

import { bodyMatchesAny, isJsonContentType } from "./body";

describe("matchesBody", () => {
  it("should return true when any pattern matches", () => {
    const patterns = [/error/i, /warning/i, /debug/i];
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
      body: "This is an error message",
    });

    expect(bodyMatchesAny(request, patterns)).toBe(true);
  });

  it("should return false when no patterns match", () => {
    const patterns = [/error/i, /warning/i, /debug/i];
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
      body: "This is a normal message",
    });

    expect(bodyMatchesAny(request, patterns)).toBe(false);
  });

  it("should work with Response objects", () => {
    const patterns = [/error/i, /warning/i, /debug/i];
    const response = createMockResponse({
      id: "1",
      code: 200,
      headers: { "content-type": ["text/html"] },
      body: "This is a warning message",
    });

    expect(bodyMatchesAny(response, patterns)).toBe(true);
  });

  it("should return false when body is undefined", () => {
    const patterns = [/error/i, /warning/i, /debug/i];
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
      body: undefined,
    });

    expect(bodyMatchesAny(request, patterns)).toBe(false);
  });

  it("should handle empty patterns array", () => {
    const patterns: RegExp[] = [];
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
      body: "This is a message",
    });

    expect(bodyMatchesAny(request, patterns)).toBe(false);
  });

  it("should handle case-insensitive patterns", () => {
    const patterns = [/ERROR/i, /WARNING/i];
    const request = createMockRequest({
      id: "1",
      host: "example.com",
      method: "GET",
      path: "/",
      body: "This is an error message",
    });

    expect(bodyMatchesAny(request, patterns)).toBe(true);
  });
});

describe("isJsonContentType", () => {
  it("should return true for application/json", () => {
    expect(isJsonContentType("application/json")).toBe(true);
  });

  it("should return true for application/json with charset", () => {
    expect(isJsonContentType("application/json; charset=utf-8")).toBe(true);
  });

  it("should return true for vnd json types", () => {
    expect(isJsonContentType("application/vnd.api+json")).toBe(true);
  });

  it("should return false for text/html", () => {
    expect(isJsonContentType("text/html")).toBe(false);
  });

  it("should return false for application/octet-stream", () => {
    expect(isJsonContentType("application/octet-stream")).toBe(false);
  });

  it("should be case-insensitive", () => {
    expect(isJsonContentType("Application/JSON")).toBe(true);
  });

  it("should return false for empty string", () => {
    expect(isJsonContentType("")).toBe(false);
  });
});
