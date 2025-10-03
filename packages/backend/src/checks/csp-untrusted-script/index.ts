import { defineCheck, done, Severity } from "engine";

import { CSPParser } from "../../parsers/csp";
import { keyStrategy } from "../../utils";

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

    // Find script-src directive
    const scriptSrcDirective = parsedCsp.directives.find(
      (d) => d.name === "script-src"
    );

    // If no script-src directive, check default-src
    const effectiveDirective = scriptSrcDirective || parsedCsp.directives.find(
      (d) => d.name === "default-src"
    );

    if (!effectiveDirective) {
      return done({ state });
    }

    const findings = [];

    // Check for unsafe-inline in script-src
    if (effectiveDirective.values.includes("'unsafe-inline'")) {
      findings.push({
        name: "Content security policy: allows untrusted script execution",
        description: `The Content Security Policy allows inline scripts with 'unsafe-inline', which can lead to XSS attacks.

**CSP Header:** \`${cspValue}\`

**Directive:** \`${effectiveDirective.name}\`

**Unsafe Values:** \`'unsafe-inline'\`

**Impact:** 
- XSS attacks can execute malicious inline scripts
- Inline event handlers can be exploited
- Data exfiltration through malicious scripts

**Recommendation:** Remove 'unsafe-inline' from script-src and use nonces or hashes for inline scripts, or move inline scripts to external files.`,
        severity: Severity.HIGH,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      });
    }

    // Check for unsafe-eval in script-src
    if (effectiveDirective.values.includes("'unsafe-eval'")) {
      findings.push({
        name: "Content security policy: allows untrusted script execution",
        description: `The Content Security Policy allows eval() and similar functions with 'unsafe-eval', which can lead to code injection attacks.

**CSP Header:** \`${cspValue}\`

**Directive:** \`${effectiveDirective.name}\`

**Unsafe Values:** \`'unsafe-eval'\`

**Impact:** 
- Code injection attacks can execute arbitrary JavaScript
- Dynamic code execution vulnerabilities
- Bypass of CSP protections

**Recommendation:** Remove 'unsafe-eval' from script-src unless absolutely necessary for legitimate use cases like templating engines.`,
        severity: Severity.HIGH,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      });
    }

    // Check for wildcard sources
    if (effectiveDirective.values.includes("*")) {
      findings.push({
        name: "Content security policy: allows untrusted script execution",
        description: `The Content Security Policy allows scripts from any source with wildcard (*), which can lead to XSS attacks.

**CSP Header:** \`${cspValue}\`

**Directive:** \`${effectiveDirective.name}\`

**Unsafe Values:** \`*\`

**Impact:** 
- Any external script can be loaded, including malicious ones
- XSS attacks can load scripts from any domain
- Complete bypass of CSP script restrictions

**Recommendation:** Replace wildcard (*) with specific trusted domains or use 'self' for same-origin resources only.`,
        severity: Severity.CRITICAL,
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
        name: "Content security policy: allows untrusted script execution",
        description: `The Content Security Policy allows scripts from data: and blob: sources, which can lead to XSS attacks.

**CSP Header:** \`${cspValue}\`

**Directive:** \`${effectiveDirective.name}\`

**Unsafe Sources:** \`${unsafeSources.join(", ")}\`

**Impact:** 
- Data URLs can contain malicious JavaScript
- Blob URLs can be used to inject malicious scripts
- XSS attacks can execute arbitrary code

**Recommendation:** Remove data: and blob: sources from script-src unless absolutely necessary for legitimate use cases.`,
        severity: Severity.HIGH,
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
        name: "Content security policy: allows untrusted script execution",
        description: `The Content Security Policy allows scripts from HTTP sources, which can be intercepted and modified.

**CSP Header:** \`${cspValue}\`

**Directive:** \`${effectiveDirective.name}\`

**HTTP Sources:** \`${httpSources.join(", ")}\`

**Impact:** 
- HTTP resources can be intercepted and modified by attackers
- Man-in-the-middle attacks can inject malicious scripts
- Insecure transmission of JavaScript files

**Recommendation:** Use HTTPS sources only or ensure HTTP sources are from trusted, internal networks.`,
        severity: Severity.MEDIUM,
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
      id: "csp-untrusted-script",
      name: "Content security policy: allows untrusted script execution",
      description:
        "Checks for Content Security Policy directives that allow untrusted script execution, which can lead to XSS attacks",
      type: "passive",
      tags: ["csp", "security-headers", "xss", "script-src", "injection"],
      severities: [Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL],
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
