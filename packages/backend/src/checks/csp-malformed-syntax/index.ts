import { defineCheck, done, Severity } from "engine";

import { CSPParser } from "../../parsers/csp";
import { findingBuilder, keyStrategy } from "../../utils";
import { Tags } from "../tags";

export default defineCheck(({ step }) => {
  step("checkCspMalformedSyntax", (state, context) => {
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

    // Check if parsing failed - this indicates malformed syntax
    if (parsedCsp.kind === "Failed") {
      const finding = findingBuilder({
        name: "Content security policy: malformed syntax",
        severity: Severity.INFO,
        request: context.target.request,
      })
        .withDescription(
          "The Content Security Policy header contains malformed syntax that cannot be parsed.",
        )
        .withImpact(
          "Malformed CSP headers will be ignored by browsers, leaving the application vulnerable to XSS and other attacks.",
        )
        .withRecommendation(
          "Fix the CSP syntax by ensuring proper formatting, valid directive names, and correct values.",
        )
        .withArtifacts("CSP Header", [cspValue])
        .build();

      return done({ state, findings: [finding] });
    }

    return done({ state });
  });

  return {
    metadata: {
      id: "csp-malformed-syntax",
      name: "Content security policy: malformed syntax",
      description:
        "Checks for malformed Content Security Policy headers that may be ignored by browsers",
      type: "passive",
      tags: [Tags.CSP, Tags.SECURITY_HEADERS, Tags.SYNTAX, Tags.VALIDATION],
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
