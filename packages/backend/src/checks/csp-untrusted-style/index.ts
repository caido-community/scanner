import { defineCheck, done, Severity } from "engine";

import { CSPParser } from "../../parsers/csp";
import { findingBuilder, keyStrategy } from "../../utils";
import { Tags } from "../tags";

export default defineCheck<unknown>(({ step }) => {
  step("checkCspUntrustedStyle", (state, context) => {
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

    // Find style-src directive
    const styleSrcDirective = parsedCsp.directives.find(
      (d) => d.name === "style-src",
    );

    // If no style-src directive, check default-src
    const effectiveDirective =
      styleSrcDirective ||
      parsedCsp.directives.find((d) => d.name === "default-src");

    if (!effectiveDirective) {
      return done({ state });
    }

    // Collect all unsafe values found (excluding 'unsafe-eval' which is not relevant for styles)
    const unsafeValues = effectiveDirective.values.filter((value) => {
      return (
        value === "'unsafe-inline'" ||
        value === "*" ||
        value.startsWith("data:") ||
        value.startsWith("blob:")
      );
    });

    // If no unsafe values found, no finding
    if (unsafeValues.length === 0) {
      return done({ state });
    }

    const finding = findingBuilder({
      name: "Content security policy: allows untrusted style execution",
      severity: Severity.INFO,
      request: context.target.request,
    })
      .withDescription(
        "The Content Security Policy allows untrusted style execution through unsafe directives in style-src or default-src.",
      )
      .withImpact(
        "Unsafe style directives can lead to CSS injection attacks, allowing malicious styles to steal sensitive data through CSS selectors, modify page appearance, and perform data exfiltration.",
      )
      .withRecommendation(
        "Remove unsafe directives like 'unsafe-inline', wildcards (*), and data:/blob: URLs from style-src. Use secure alternatives like nonces (nonce-RANDOM) with at least 8 characters.",
      )
      .withArtifacts("Unsafe Values", unsafeValues)
      .build();

    return done({ state, findings: [finding] });
  });

  return {
    metadata: {
      id: "csp-untrusted-style",
      name: "Content security policy: allows untrusted style execution",
      description:
        "Mitigate CSS injection by avoiding 'unsafe-inline', data: URLs, and global wildcards in style directives. Use a secure, random nonce of at least 8 characters 'nonce-RANDOM' to prevent untrusted style execution.",
      type: "passive",
      tags: [
        Tags.CSP,
        Tags.SECURITY_HEADERS,
        Tags.CSS_INJECTION,
        Tags.STYLE_SRC,
        Tags.INJECTION,
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
