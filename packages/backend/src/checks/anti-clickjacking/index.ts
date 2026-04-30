import { defineCheck, done, Severity } from "engine";

import { keyStrategy } from "../../utils/key";
import { Tags } from "../tags";

export default defineCheck<unknown>(({ step }) => {
  step("checkAntiClickjacking", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    // Only check HTML responses
    const contentType = response.getHeader("content-type")?.[0] ?? "";
    if (contentType === undefined || !contentType.includes("text/html")) {
      return done({ state });
    }

    const xFrameOptions = response.getHeader("x-frame-options");
    const cspHeader = response.getHeader("content-security-policy");

    // Check if CSP has frame-ancestors directive
    let hasCspFrameAncestors = false;
    if (cspHeader && cspHeader.length > 0) {
      const cspValue = cspHeader[0]?.toLowerCase() ?? "";
      hasCspFrameAncestors = cspValue.includes("frame-ancestors");
    }

    // If CSP has frame-ancestors, X-Frame-Options is not needed
    if (hasCspFrameAncestors) {
      return done({ state });
    }

    // Check X-Frame-Options header
    if (!xFrameOptions || xFrameOptions.length === 0) {
      const finding = {
        name: "Missing X-Frame-Options Header",
        description: `The application does not include an X-Frame-Options header, which can help prevent clickjacking attacks. Without this header, the application may be vulnerable to being embedded in frames on malicious websites.`,
        severity: Severity.MEDIUM,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      };

      return done({ state, findings: [finding] });
    }

    // Check for multiple X-Frame-Options headers
    if (xFrameOptions.length > 1) {
      const finding = {
        name: "Multiple X-Frame-Options Headers",
        description: `The application returns multiple X-Frame-Options headers, which may cause inconsistent behavior across different browsers. Only one X-Frame-Options header should be present.`,
        severity: Severity.LOW,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      };

      return done({ state, findings: [finding] });
    }

    // Check for malformed X-Frame-Options values
    const xFrameValue = xFrameOptions[0]?.toLowerCase() ?? "";
    if (!xFrameValue.includes("deny") && !xFrameValue.includes("sameorigin")) {
      const finding = {
        name: "Malformed X-Frame-Options Header",
        description: `The X-Frame-Options header has an invalid value. Valid values are 'DENY', 'SAMEORIGIN', or 'ALLOW-FROM <uri>'. The current value may not provide adequate protection against clickjacking.`,
        severity: Severity.LOW,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      };

      return done({ state, findings: [finding] });
    }

    return done({ state });
  });

  return {
    metadata: {
      id: "anti-clickjacking",
      name: "Anti-Clickjacking Protection",
      description:
        "Checks for proper X-Frame-Options header implementation to prevent clickjacking attacks",
      type: "passive",
      tags: [Tags.CLICKJACKING, Tags.SECURITY_HEADERS, Tags.X_FRAME_OPTIONS],
      severities: [Severity.MEDIUM, Severity.LOW],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: (context) => context.response !== undefined,
  };
});
