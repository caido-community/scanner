import { describe, expect, it } from "vitest";

import { CSPParser } from "./csp";

describe("CSPParser", () => {
  describe("parse", () => {
    it("should parse a simple CSP header", () => {
      const cspHeader = "default-src 'self'; script-src 'self' 'unsafe-inline'";
      const result = CSPParser.parse(cspHeader);

      expect(result.raw).toBe(cspHeader);
      expect(result.directives).toHaveLength(2);
      expect(result.directives[0]).toEqual({
        name: "default-src",
        values: ["'self'"],
      });
      expect(result.directives[1]).toEqual({
        name: "script-src",
        values: ["'self'", "'unsafe-inline'"],
      });
    });

    it("should parse CSP with multiple values per directive", () => {
      const cspHeader = "script-src 'self' https://example.com 'unsafe-inline'";
      const result = CSPParser.parse(cspHeader);

      expect(result.directives).toHaveLength(1);
      expect(result.directives[0]).toEqual({
        name: "script-src",
        values: ["'self'", "https://example.com", "'unsafe-inline'"],
      });
    });

    it("should handle empty CSP header", () => {
      const result = CSPParser.parse("");
      expect(result.directives).toHaveLength(0);
      expect(result.raw).toBe("");
    });

    it("should handle CSP header with only whitespace", () => {
      const result = CSPParser.parse("   ");
      expect(result.directives).toHaveLength(0);
      expect(result.raw).toBe("   ");
    });

    it("should handle CSP header with extra semicolons", () => {
      const cspHeader = "default-src 'self';; script-src 'self';;";
      const result = CSPParser.parse(cspHeader);

      expect(result.directives).toHaveLength(2);
      expect(result.directives[0]?.name).toBe("default-src");
      expect(result.directives[1]?.name).toBe("script-src");
    });

    it("should handle CSP header with spaces around semicolons", () => {
      const cspHeader =
        "default-src 'self' ; script-src 'self' ; style-src 'self'";
      const result = CSPParser.parse(cspHeader);

      expect(result.directives).toHaveLength(3);
      expect(result.directives[0]?.name).toBe("default-src");
      expect(result.directives[1]?.name).toBe("script-src");
      expect(result.directives[2]?.name).toBe("style-src");
    });

    it("should handle directive with no values", () => {
      const cspHeader = "default-src 'self'; object-src";
      const result = CSPParser.parse(cspHeader);

      expect(result.directives).toHaveLength(2);
      expect(result.directives[0]).toEqual({
        name: "default-src",
        values: ["'self'"],
      });
      expect(result.directives[1]).toEqual({
        name: "object-src",
        values: [],
      });
    });
  });
});
