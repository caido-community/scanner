import { defineCheck, done, Severity } from "engine";

import { CSPParser } from "../../parsers/csp";
import { keyStrategy } from "../../utils";

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

    // Find style-src directive
    const styleSrcDirective = parsedCsp.directives.find(
      (d) => d.name === "style-src"
    );

    // If no style-src directive, check default-src
    const effectiveDirective = styleSrcDirective || parsedCsp.directives.find(
      (d) => d.name === "default-src"
    );

    if (!effectiveDirective) {
      return done({ state });
    }

    const findings = [];

    // Check for unsafe-inline in style-src
    if (effectiveDirective.values.includes("'unsafe-inline'")) {
      findings.push({
        name: "Content security policy: allows untrusted style execution",
        description: `The Content Security Policy allows inline styles with 'unsafe-inline', which can lead to CSS injection attacks.

**CSP Header:** \`${cspValue}\`

**Directive:** \`${effectiveDirective.name}\`

**Unsafe Values:** \`'unsafe-inline'\`

**Impact:** 
- CSS injection attacks can steal sensitive data through CSS selectors
- Malicious styles can be injected to modify page appearance
- Data exfiltration through CSS-based attacks

**Recommendation:** Remove 'unsafe-inline' from style-src and use nonces or hashes for inline styles, or move inline styles to external stylesheets.`,
        severity: Severity.MEDIUM,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      });
    }

    // Check for wildcard sources
    if (effectiveDirective.values.includes("*")) {
      findings.push({
        name: "Content security policy: allows untrusted style execution",
        description: `The Content Security Policy allows styles from any source with wildcard (*), which can lead to CSS injection attacks.

**CSP Header:** \`${cspValue}\`

**Directive:** \`${effectiveDirective.name}\`

**Unsafe Values:** \`*\`

**Impact:** 
- Any external stylesheet can be loaded, including malicious ones
- CSS injection attacks can steal sensitive data
- Malicious styles can be injected from any domain

**Recommendation:** Replace wildcard (*) with specific trusted domains or use 'self' for same-origin resources only.`,
        severity: Severity.HIGH,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      });
    }

    // Check for data: and blob: sources
    const unsafeSources = effectiveDirective.values.filter(
      (value) => value.startsWith("data:") || value.startsWith("blob:")
    );

    if (unsafeSources.length > 0) {
      findings.push({
        name: "Content security policy: allows untrusted style execution",
        description: `The Content Security Policy allows styles from data: and blob: sources, which can lead to CSS injection attacks.

**CSP Header:** \`${cspValue}\`

**Directive:** \`${effectiveDirective.name}\`

**Unsafe Sources:** \`${unsafeSources.join(", ")}\`

**Impact:** 
- Data URLs can contain malicious CSS
- Blob URLs can be used to inject malicious styles
- CSS injection attacks can steal sensitive data

**Recommendation:** Remove data: and blob: sources from style-src unless absolutely necessary for legitimate use cases.`,
        severity: Severity.MEDIUM,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      });
    }

    // Check for overly permissive sources (http: without https:)
    const httpSources = effectiveDirective.values.filter(
      (value) => value.startsWith("http:") && !value.startsWith("https:")
    );

    if (httpSources.length > 0) {
      findings.push({
        name: "Content security policy: allows untrusted style execution",
        description: `The Content Security Policy allows styles from HTTP sources, which can be intercepted and modified.

**CSP Header:** \`${cspValue}\`

**Directive:** \`${effectiveDirective.name}\`

**HTTP Sources:** \`${httpSources.join(", ")}\`

**Impact:** 
- HTTP resources can be intercepted and modified by attackers
- Man-in-the-middle attacks can inject malicious CSS
- Insecure transmission of stylesheets

**Recommendation:** Use HTTPS sources only or ensure HTTP sources are from trusted, internal networks.`,
        severity: Severity.LOW,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      });
    }

    return done({ state, findings });
  });

  return {
    metadata: {
      id: "csp-untrusted-style",
      name: "Content security policy: allows untrusted style execution",
      description:
        "Checks for Content Security Policy directives that allow untrusted style execution, which can lead to CSS injection attacks",
      type: "passive",
      tags: ["csp", "security-headers", "css-injection", "style-src"],
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
