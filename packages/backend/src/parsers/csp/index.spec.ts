import { describe, expect, it } from "vitest";

import { CSPParser } from ".";

describe("CSPParser", () => {
  describe("parse", () => {
    it("should parse a simple CSP header", () => {
      const cspHeader = "default-src 'self'; script-src 'self' 'unsafe-inline'";
      const result = CSPParser.parse(cspHeader);

      expect(result).toMatchObject({
        kind: "Success",
        raw: cspHeader,
        directives: [
          {
            name: "default-src",
            values: ["'self'"],
          },
          {
            name: "script-src",
            values: ["'self'", "'unsafe-inline'"],
          },
        ],
      });
    });

    it("should parse CSP with multiple values per directive", () => {
      const cspHeader = "script-src 'self' https://example.com 'unsafe-inline'";
      const result = CSPParser.parse(cspHeader);

      expect(result).toMatchObject({
        kind: "Success",
        raw: cspHeader,
        directives: [
          {
            name: "script-src",
            values: ["'self'", "https://example.com", "'unsafe-inline'"],
          },
        ],
      });
    });

    it("should handle empty CSP header", () => {
      const result = CSPParser.parse("");
      expect(result).toMatchObject({
        kind: "Success",
        raw: "",
        directives: [],
      });
    });

    it("should handle CSP header with only whitespace", () => {
      const result = CSPParser.parse("   ");
      expect(result).toMatchObject({
        kind: "Success",
        raw: "   ",
        directives: [],
      });
    });

    it("should handle CSP header with extra semicolons", () => {
      const cspHeader = "default-src 'self';; script-src 'self';;";
      const result = CSPParser.parse(cspHeader);

      expect(result).toMatchObject({
        kind: "Success",
        raw: cspHeader,
        directives: [{ name: "default-src" }, { name: "script-src" }],
      });
    });

    it("should handle CSP header with spaces around semicolons", () => {
      const cspHeader =
        "default-src 'self' ; script-src 'self' ; style-src 'self'";
      const result = CSPParser.parse(cspHeader);

      expect(result).toMatchObject({
        kind: "Success",
        raw: cspHeader,
        directives: [
          { name: "default-src" },
          { name: "script-src" },
          { name: "style-src" },
        ],
      });
    });

    it("should handle directive with no values", () => {
      const cspHeader = "default-src 'self'; object-src";
      const result = CSPParser.parse(cspHeader);

      expect(result).toMatchObject({
        kind: "Success",
        raw: cspHeader,
        directives: [
          {
            name: "default-src",
            values: ["'self'"],
          },
          {
            name: "object-src",
            values: [],
          },
        ],
      });
    });
  });
});
