import { defineCheck, done, Severity } from "engine";

import { CSPParser } from "../../parsers/csp";
import { findingBuilder, keyStrategy } from "../../utils";
import { Tags } from "../tags";

export default defineCheck(({ step }) => {
  step("checkCspFormHijacking", (state, context) => {
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

    // Find form-action directive
    const formActionDirective = parsedCsp.directives.find(
      (d) => d.name === "form-action",
    );

    // Check if form-action directive is missing
    if (!formActionDirective) {
      const finding = findingBuilder({
        name: "Content security policy: allows form hijacking",
        severity: Severity.INFO,
        request: context.target.request,
      })
        .withDescription(
          "The Content Security Policy is missing the form-action directive.",
        )
        .withImpact(
          "Forms can be submitted to any destination, allowing form hijacking attacks that redirect form submissions to malicious endpoints.",
        )
        .withRecommendation(
          "Add a form-action directive to restrict where forms can be submitted. Use 'self' to allow only same-origin submissions, or 'none' to prevent all form submissions.",
        )
        .withArtifacts("CSP Header", [cspValue])
        .build();

      return done({ state, findings: [finding] });
    }

    // Check for overly permissive form-action values
    const isSelfOrNone = formActionDirective.values.every(
      (value) => value === "'self'" || value === "'none'",
    );

    if (isSelfOrNone) {
      return done({ state });
    }

    const unsafeValues = formActionDirective.values.filter(
      (value) => value !== "'self'" && value !== "'none'",
    );

    const finding = findingBuilder({
      name: "Content security policy: allows form hijacking",
      severity: Severity.INFO,
      request: context.target.request,
    })
      .withDescription(
        "The content security policy allows forms to be submitted to destinations other than 'self' or 'none'.",
      )
      .withImpact(
        "Forms can be submitted to external or untrusted destinations, allowing form hijacking attacks that redirect form submissions to malicious endpoints.",
      )
      .withRecommendation(
        "Restrict form submissions to 'self' or 'none' to prevent form hijacking attacks.",
      )
      .withArtifacts("Unsafe Values", unsafeValues)
      .build();

    return done({ state, findings: [finding] });
  });

  return {
    metadata: {
      id: "csp-form-hijacking",
      name: "Content security policy: allows form hijacking",
      description:
        "Checks for missing or overly permissive form-action directives in Content Security Policy headers, which can lead to form hijacking attacks",
      type: "passive",
      tags: [
        Tags.CSP,
        Tags.SECURITY_HEADERS,
        Tags.FORM_HIJACKING,
        Tags.FORM_ACTION,
        Tags.CSRF,
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
