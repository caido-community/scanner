import { defineCheck, done, Severity } from "engine";

import { CSPParser } from "../../parsers/csp";
import { findingBuilder, keyStrategy } from "../../utils";
import { Tags } from "../tags";

export default defineCheck<unknown>(({ step }) => {
  step("checkCspUntrustedScript", (state, context) => {
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
      scriptSrcDirective ||
      parsedCsp.directives.find((d) => d.name === "default-src");

    if (!effectiveDirective) {
      return done({ state });
    }

    // Collect all unsafe values found
    const unsafeValues = effectiveDirective.values.filter((value) => {
      return (
        value === "'unsafe-inline'" ||
        value === "'unsafe-eval'" ||
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
      name: "Content security policy: allows untrusted script execution",
      severity: Severity.INFO,
      request: context.target.request,
    })
      .withDescription(
        "The Content Security Policy allows untrusted script execution through unsafe directives in script-src or default-src.",
      )
      .withImpact(
        "Unsafe script directives can lead to cross-site scripting (XSS) attacks, allowing malicious JavaScript execution, data exfiltration, and bypass of security controls.",
      )
      .withRecommendation(
        "Remove unsafe directives like 'unsafe-inline', 'unsafe-eval', wildcards (*), and data:/blob: URLs from script-src. Use secure alternatives like nonces (nonce-RANDOM) with at least 8 characters.",
      )
      .withArtifacts("Unsafe Values", unsafeValues)
      .build();

    return done({ state, findings: [finding] });
  });

  return {
    metadata: {
      id: "csp-untrusted-script",
      name: "Content security policy: allows untrusted script execution",
      description:
        "Mitigate cross-site scripting by avoiding 'unsafe-inline', 'unsafe-eval', data: URLs, and global wildcards in script directives. Use a secure, random nonce of at least 8 characters 'nonce-RANDOM' to prevent untrusted JavaScript execution.",
      type: "passive",
      tags: [
        Tags.CSP,
        Tags.SECURITY_HEADERS,
        Tags.XSS,
        Tags.SCRIPT_SRC,
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
