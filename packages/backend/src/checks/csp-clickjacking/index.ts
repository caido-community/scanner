import { defineCheck, done, Severity } from "engine";

import { CSPParser } from "../../parsers/csp";
import { findingBuilder, keyStrategy } from "../../utils";
import { Tags } from "../tags";

export default defineCheck(({ step }) => {
  step("checkCspClickjacking", (state, context) => {
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

    // Find frame-ancestors directive
    const frameAncestorsDirective = parsedCsp.directives.find(
      (d) => d.name === "frame-ancestors",
    );

    // Check if frame-ancestors directive is missing
    if (!frameAncestorsDirective) {
      const finding = findingBuilder({
        name: "Content security policy: allows clickjacking",
        severity: Severity.INFO,
        request: context.target.request,
      })
        .withDescription(
          "The Content Security Policy is missing the frame-ancestors directive.",
        )
        .withImpact(
          "The application can be embedded in malicious frames, allowing clickjacking attacks that trick users into performing unintended actions.",
        )
        .withRecommendation(
          "Add a frame-ancestors directive to restrict where the application can be embedded. Use 'none' to prevent all framing, or 'self' to allow only same-origin framing.",
        )
        .withArtifacts("CSP Header", [cspValue])
        .build();

      return done({ state, findings: [finding] });
    }

    // Check for overly permissive frame-ancestors values
    const isSelfOrNone = frameAncestorsDirective.values.every(
      (value) => value === "'self'" || value === "'none'",
    );

    if (isSelfOrNone) {
      return done({ state });
    }

    const unsafeValues = frameAncestorsDirective.values.filter(
      (value) => value !== "'self'" && value !== "'none'",
    );

    const finding = findingBuilder({
      name: "Content security policy: allows clickjacking",
      severity: Severity.INFO,
      request: context.target.request,
    })
      .withDescription(
        "The content security policy allows the application to be embedded in frames from sources other than 'self' or 'none'.",
      )
      .withImpact(
        "The application can be embedded in malicious frames, allowing clickjacking attacks that trick users into performing unintended actions.",
      )
      .withRecommendation(
        "Restrict the application to be embedded in frames from 'self' or 'none'.",
      )
      .withArtifacts("Unsafe Values", unsafeValues)
      .build();

    return done({ state, findings: [finding] });
  });

  return {
    metadata: {
      id: "csp-clickjacking",
      name: "Content security policy: allows clickjacking",
      description:
        "Checks for missing or overly permissive frame-ancestors directives in Content Security Policy headers, which can lead to clickjacking attacks",
      type: "passive",
      tags: [
        Tags.CSP,
        Tags.SECURITY_HEADERS,
        Tags.CLICKJACKING,
        Tags.FRAME_ANCESTORS,
        Tags.UI_REDRESSING,
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
