import { describe, expect, it } from "vitest";

import { Result } from "../../types/result";

import {
  createUrlBypassGenerator,
  getAllUrlBypassTechniques,
  validateUrlBypassGeneratorConfig,
} from "./url-bypass";

describe("url bypass generator", () => {
  it("exposes all available techniques", () => {
    const techniques = getAllUrlBypassTechniques();
    expect(techniques).toContain("NormalUrl");
    expect(techniques).toContain("UserInfoBypass");
    expect(techniques.length).toBeGreaterThan(5);
  });

  it("supports only, except and limit composition", () => {
    const result = createUrlBypassGenerator({
      expectedHost: "example.com",
      attackerHost: "attacker.test",
      protocol: "https:",
    });
    expect(Result.isOk(result)).toBe(true);
    const generator = Result.isOk(result) ? result.value : undefined;
    expect(generator).toBeDefined();

    const only = Array.from(generator!.only("NormalUrl", "SchemeRelative")).map(
      (payload) => payload.technique,
    );
    expect(only).toEqual(["NormalUrl", "SchemeRelative"]);

    const except = Array.from(generator!.except("NormalUrl")).map(
      (payload) => payload.technique,
    );
    expect(except.includes("NormalUrl")).toBe(false);

    const limited = Array.from(generator!.limit(2)).map(
      (payload) => payload.technique,
    );
    expect(limited).toHaveLength(2);
  });

  it("validates redirects using payload-specific validator", () => {
    const result = createUrlBypassGenerator({
      expectedHost: "example.com",
      attackerHost: "attacker.test",
      protocol: "https:",
    });
    expect(Result.isOk(result)).toBe(true);
    const generator = Result.isOk(result) ? result.value : undefined;
    expect(generator).toBeDefined();
    const normal = Array.from(generator!.only("NormalUrl"))[0];
    expect(normal).toBeDefined();

    if (normal !== undefined) {
      const payload = normal.generate();
      expect(payload.validatesWith(new URL("https://attacker.test/path"))).toBe(
        true,
      );
      expect(payload.validatesWith(new URL("https://example.com/path"))).toBe(
        false,
      );
    }
  });

  it("enables contains bypass only when original value exists", () => {
    const withoutResult = createUrlBypassGenerator({
      expectedHost: "example.com",
      attackerHost: "attacker.test",
      protocol: "https:",
    });
    expect(Result.isOk(withoutResult)).toBe(true);
    const withoutOriginal = Array.from(
      Result.isOk(withoutResult) ? withoutResult.value : [],
    ).map((payload) => payload.technique);

    const withResult = createUrlBypassGenerator({
      expectedHost: "example.com",
      attackerHost: "attacker.test",
      protocol: "https:",
      originalValue: "https://example.com/profile",
    });
    expect(Result.isOk(withResult)).toBe(true);
    const withOriginal = Array.from(
      Result.isOk(withResult) ? withResult.value : [],
    ).map((payload) => payload.technique);

    expect(withoutOriginal.includes("ContainsBypass")).toBe(false);
    expect(withOriginal.includes("ContainsBypass")).toBe(true);
  });

  it("returns error for invalid config", () => {
    const result = createUrlBypassGenerator({
      expectedHost: "https://example.com",
      attackerHost: "attacker.test",
      protocol: "https:",
    });
    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error).toBe(
        "[createUrlBypassGenerator] Expected a valid hostname, not a URL",
      );
    }
  });
});

describe("url bypass validation", () => {
  it("rejects URL-like hosts", () => {
    const result = validateUrlBypassGeneratorConfig({
      expectedHost: "https://example.com",
      attackerHost: "attacker.test",
      protocol: "https:",
    });
    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error).toBe(
        "[createUrlBypassGenerator] Expected a valid hostname, not a URL",
      );
    }
  });

  it("rejects protocol without colon", () => {
    const result = validateUrlBypassGeneratorConfig({
      expectedHost: "example.com",
      attackerHost: "attacker.test",
      protocol: "https",
    });
    expect(Result.isErr(result)).toBe(true);
    if (Result.isErr(result)) {
      expect(result.error).toBe(
        "[createUrlBypassGenerator] Protocol must end with a colon",
      );
    }
  });
});
