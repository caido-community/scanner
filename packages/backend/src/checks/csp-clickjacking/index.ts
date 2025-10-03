import { defineCheck, done, Severity } from "engine";

import { CSPParser } from "../../parsers/csp";
import { keyStrategy } from "../../utils";

export default defineCheck<unknown>(({ step }) => {
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

    // Find frame-ancestors directive
    const frameAncestorsDirective = parsedCsp.directives.find(
      (d) => d.name === "frame-ancestors"
    );

    const findings = [];

    // Check if frame-ancestors directive is missing
    if (!frameAncestorsDirective) {
      findings.push({
        name: "Content security policy: allows clickjacking",
        description: `The Content Security Policy is missing the frame-ancestors directive, which can lead to clickjacking attacks.

**CSP Header:** \`${cspValue}\`

**Missing Directive:** \`frame-ancestors\`

**Impact:** 
- The application can be embedded in malicious frames
- Clickjacking attacks can trick users into performing unintended actions
- UI redressing attacks can overlay malicious content
- Cross-site request forgery through iframe embedding

**Recommendation:** Add a frame-ancestors directive to restrict where the application can be embedded. Use 'none' to prevent all framing, or 'self' to allow only same-origin framing.`,
        severity: Severity.MEDIUM,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      });
    } else {
      // Check for overly permissive frame-ancestors values
      const frameAncestorsValues = frameAncestorsDirective.values;

      // Check for wildcard
      if (frameAncestorsValues.includes("*")) {
        findings.push({
          name: "Content security policy: allows clickjacking",
          description: `The Content Security Policy allows the application to be embedded in frames from any source with wildcard (*), which can lead to clickjacking attacks.

**CSP Header:** \`${cspValue}\`

**Directive:** \`frame-ancestors\`

**Unsafe Values:** \`*\`

**Impact:** 
- The application can be embedded in malicious frames from any domain
- Complete bypass of frame embedding restrictions
- Clickjacking attacks can be performed from any malicious site

**Recommendation:** Replace wildcard (*) with specific trusted domains or use 'self' for same-origin framing only.`,
          severity: Severity.HIGH,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        });
      }

      // Check for data: and blob: sources
      const unsafeSources = frameAncestorsValues.filter(
        (value) => value.startsWith("data:") || value.startsWith("blob:")
      );

      if (unsafeSources.length > 0) {
        findings.push({
          name: "Content security policy: allows clickjacking",
          description: `The Content Security Policy allows the application to be embedded in frames from data: and blob: sources, which can lead to clickjacking attacks.

**CSP Header:** \`${cspValue}\`

**Directive:** \`frame-ancestors\`

**Unsafe Sources:** \`${unsafeSources.join(", ")}\`

**Impact:** 
- The application can be embedded in data URL frames
- Clickjacking attacks can be performed through data URLs
- Bypass of frame embedding restrictions

**Recommendation:** Remove data: and blob: sources from frame-ancestors unless absolutely necessary for legitimate use cases.`,
          severity: Severity.MEDIUM,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        });
      }

      // Check for HTTP sources without HTTPS
      const httpSources = frameAncestorsValues.filter(
        (value) => value.startsWith("http:") && !value.startsWith("https:")
      );

      if (httpSources.length > 0) {
        findings.push({
          name: "Content security policy: allows clickjacking",
          description: `The Content Security Policy allows the application to be embedded in frames from HTTP sources, which can be intercepted and modified.

**CSP Header:** \`${cspValue}\`

**Directive:** \`frame-ancestors\`

**HTTP Sources:** \`${httpSources.join(", ")}\`

**Impact:** 
- HTTP frame sources can be intercepted by attackers
- Man-in-the-middle attacks can modify frame content
- Insecure transmission of frame embedding permissions

**Recommendation:** Use HTTPS sources only or ensure HTTP sources are from trusted, internal networks.`,
          severity: Severity.LOW,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        });
      }
    }

    return done({ state, findings });
  });

  return {
    metadata: {
      id: "csp-clickjacking",
      name: "Content security policy: allows clickjacking",
      description:
        "Checks for missing or overly permissive frame-ancestors directives in Content Security Policy headers, which can lead to clickjacking attacks",
      type: "passive",
      tags: ["csp", "security-headers", "clickjacking", "frame-ancestors", "ui-redressing"],
      severities: [Severity.LOW, Severity.MEDIUM, Severity.HIGH],
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
