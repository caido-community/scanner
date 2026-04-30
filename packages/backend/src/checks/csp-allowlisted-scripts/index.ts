import { defineCheck, done, Severity } from "engine";

import { CSPParser } from "../../parsers/csp";
import { keyStrategy } from "../../utils";
import { findingBuilder } from "../../utils/findings";
import { Tags } from "../tags";

export default defineCheck(({ step }) => {
  step("checkCspAllowlistedScripts", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    // Only check HTML responses
    const contentType = response.getHeader("content-type")?.[0] ?? "";
    if (contentType === undefined || !contentType.includes("text/html")) {
      return done({ state });
    }

    const cspHeader = response.getHeader("content-security-policy");

    // Check if CSP header is missing
    if (!cspHeader || cspHeader.length === 0) {
      return done({ state });
    }

    const cspValue = cspHeader[0] ?? "";
    const parsedCsp = CSPParser.parse(cspValue);

    // Check if parsing was successful
    if (parsedCsp.kind === "Failed") {
      return done({ state });
    }

    // Find script-src directive
    const scriptSrcDirective = parsedCsp.directives.find(
      (d) => d.name === "script-src",
    );

    // If no script-src directive, check default-src
    const effectiveDirective =
      scriptSrcDirective ??
      parsedCsp.directives.find((d) => d.name === "default-src");

    if (!effectiveDirective) {
      return done({ state });
    }

    // Check for too many external domains (more than 5)
    const allowlistedResources = effectiveDirective.values.filter(
      (source) =>
        source.startsWith("http://") ||
        source.startsWith("https://") ||
        source.startsWith("//"),
    );

    if (allowlistedResources.length >= 1) {
      const finding = findingBuilder({
        name: "Content security policy: allowlisted script resources",
        severity: Severity.INFO,
        request: context.target.request,
      })
        .withDescription(
          "The website's Content Security Policy allows specific script sources instead of using nonces or hashes. ",
        )
        .withImpact(
          "This weakens protection against injected scripts, as allowlisted sources can still be exploited if compromised.",
        )
        .withRecommendation(
          "Use nonces or hashes instead of allowlisting external resources.",
        )
        .withArtifacts("Allowlisted Resources", allowlistedResources)
        .build();

      return done({ state, findings: [finding] });
    }

    return done({ state });
  });

  return {
    metadata: {
      id: "csp-allowlisted-scripts",
      name: "Content security policy: allowlisted script resources",
      description:
        "Checks for overly permissive script-src directives in Content Security Policy headers that allow specific script sources instead of using nonces or hashes",
      type: "passive",
      tags: [
        Tags.CSP,
        Tags.SECURITY_HEADERS,
        Tags.SCRIPT_SRC,
        Tags.SUPPLY_CHAIN,
        Tags.ATTACK_SURFACE,
      ],
      severities: [Severity.INFO],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: (context) => {
      if (context.response === undefined) return false;
      const contentType = context.response.getHeader("content-type")?.[0] ?? "";
      return contentType.includes("text/html");
    },
  };
});
