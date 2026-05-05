import { defineCheck, done, Severity } from "engine";

import { findingBuilder, keyStrategy } from "../../utils";
import { Tags } from "../tags";

export default defineCheck(({ step }) => {
  step("checkCspNotEnforced", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    // Only check HTML responses
    const contentType = response.getHeader("content-type")?.[0] ?? "";
    if (contentType === undefined || !contentType.includes("text/html")) {
      return done({ state });
    }

    const cspReportOnlyHeader = response.getHeader(
      "content-security-policy-report-only",
    );
    const cspHeader = response.getHeader("content-security-policy");

    // Check if CSP is in report-only mode (not enforced) and no regular CSP header exists
    if (
      cspReportOnlyHeader &&
      cspReportOnlyHeader.length > 0 &&
      (!cspHeader || cspHeader.length === 0)
    ) {
      const cspValue = cspReportOnlyHeader[0] ?? "";
      const finding = findingBuilder({
        name: "Content security policy: not enforced",
        severity: Severity.INFO,
        request: context.target.request,
      })
        .withDescription(
          "The application uses Content-Security-Policy-Report-Only header without a regular Content-Security-Policy header, which means the CSP is not enforced and only reports violations.",
        )
        .withImpact(
          "CSP in report-only mode provides no actual protection against XSS and other attacks, as violations are only logged but not blocked.",
        )
        .withRecommendation(
          "Replace Content-Security-Policy-Report-Only with Content-Security-Policy to enforce the policy and provide actual security protection.",
        )
        .withArtifacts("CSP Report-Only Header", [cspValue])
        .build();

      return done({ state, findings: [finding] });
    }

    return done({ state });
  });

  return {
    metadata: {
      id: "csp-not-enforced",
      name: "Content security policy: not enforced",
      description:
        "Checks for Content-Security-Policy-Report-Only headers, which indicate CSP is not enforced and only reports violations",
      type: "passive",
      tags: [
        Tags.CSP,
        Tags.SECURITY_HEADERS,
        Tags.REPORT_ONLY,
        Tags.ENFORCEMENT,
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
