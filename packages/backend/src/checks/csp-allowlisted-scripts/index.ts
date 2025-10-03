import { defineCheck, done, Severity } from "engine";

import { CSPParser } from "../../parsers/csp";
import { keyStrategy } from "../../utils";

export default defineCheck<unknown>(({ step }) => {
  step("checkCspAllowlistedScripts", (state, context) => {
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

    // Check for overly permissive script sources
    const scriptSources = effectiveDirective.values;

    // Check for too many external domains (more than 5)
    const externalDomains = scriptSources.filter(
      (source) =>
        source.startsWith("http://") ||
        source.startsWith("https://") ||
        source.startsWith("//")
    );

    if (externalDomains.length > 5) {
      findings.push({
        name: "Content security policy: allowlisted script resources",
        description: `The Content Security Policy allows scripts from too many external domains, which increases the attack surface.

**CSP Header:** \`${cspValue}\`

**Directive:** \`${effectiveDirective.name}\`

**External Domains:** \`${externalDomains.length}\` (${externalDomains.join(", ")})

**Impact:** 
- Increased attack surface with multiple external script sources
- Higher risk of supply chain attacks
- Difficulty in monitoring and controlling script sources
- Potential for malicious scripts from compromised domains

**Recommendation:** Reduce the number of external script sources to only essential, trusted domains. Consider using a Content Delivery Network (CDN) or self-hosting scripts when possible.`,
        severity: Severity.MEDIUM,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      });
    }

    // Check for CDN domains that might be overly permissive
    const cdnDomains = scriptSources.filter((source) =>
      source.includes("cdn") ||
      source.includes("cloudflare") ||
      source.includes("jsdelivr") ||
      source.includes("unpkg") ||
      source.includes("cdnjs")
    );

    if (cdnDomains.length > 3) {
      findings.push({
        name: "Content security policy: allowlisted script resources",
        description: `The Content Security Policy allows scripts from multiple CDN domains, which increases the attack surface.

**CSP Header:** \`${cspValue}\`

**Directive:** \`${effectiveDirective.name}\`

**CDN Domains:** \`${cdnDomains.length}\` (${cdnDomains.join(", ")})

**Impact:** 
- Multiple CDN sources increase attack surface
- Risk of supply chain attacks from compromised CDNs
- Difficulty in monitoring script integrity
- Potential for malicious scripts from compromised CDN resources

**Recommendation:** Consolidate CDN usage to a single, trusted CDN provider or self-host critical scripts.`,
        severity: Severity.LOW,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      });
    }

    // Check for wildcard subdomains
    const wildcardSubdomains = scriptSources.filter((source) =>
      source.includes("*.") || source.includes("*.com") || source.includes("*.org")
    );

    if (wildcardSubdomains.length > 0) {
      findings.push({
        name: "Content security policy: allowlisted script resources",
        description: `The Content Security Policy allows scripts from wildcard subdomains, which can be overly permissive.

**CSP Header:** \`${cspValue}\`

**Directive:** \`${effectiveDirective.name}\`

**Wildcard Subdomains:** \`${wildcardSubdomains.join(", ")}\`

**Impact:** 
- Wildcard subdomains can include malicious or compromised subdomains
- Increased attack surface with unlimited subdomain access
- Difficulty in monitoring and controlling script sources
- Potential for subdomain takeover attacks

**Recommendation:** Replace wildcard subdomains with specific, trusted subdomains or use exact domain names.`,
        severity: Severity.MEDIUM,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      });
    }

    // Check for non-HTTPS sources
    const httpSources = scriptSources.filter(
      (source) => source.startsWith("http://") && !source.startsWith("https://")
    );

    if (httpSources.length > 0) {
      findings.push({
        name: "Content security policy: allowlisted script resources",
        description: `The Content Security Policy allows scripts from HTTP sources, which can be intercepted and modified.

**CSP Header:** \`${cspValue}\`

**Directive:** \`${effectiveDirective.name}\`

**HTTP Sources:** \`${httpSources.join(", ")}\`

**Impact:** 
- HTTP scripts can be intercepted and modified by attackers
- Man-in-the-middle attacks can inject malicious scripts
- Insecure transmission of JavaScript files
- Risk of script tampering

**Recommendation:** Use HTTPS sources only or ensure HTTP sources are from trusted, internal networks.`,
        severity: Severity.LOW,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      });
    }

    // Check for overly broad domains (e.g., *.google.com, *.microsoft.com)
    const broadDomains = scriptSources.filter((source) =>
      source.includes("*.google.com") ||
      source.includes("*.microsoft.com") ||
      source.includes("*.amazon.com") ||
      source.includes("*.cloudflare.com")
    );

    if (broadDomains.length > 0) {
      findings.push({
        name: "Content security policy: allowlisted script resources",
        description: `The Content Security Policy allows scripts from overly broad domains, which can be overly permissive.

**CSP Header:** \`${cspValue}\`

**Directive:** \`${effectiveDirective.name}\`

**Broad Domains:** \`${broadDomains.join(", ")}\`

**Impact:** 
- Broad domains include many subdomains that may not be trusted
- Increased attack surface with unlimited subdomain access
- Risk of scripts from untrusted or compromised subdomains
- Difficulty in monitoring script sources

**Recommendation:** Use specific subdomains instead of broad wildcard domains, or use exact domain names for critical scripts.`,
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
      id: "csp-allowlisted-scripts",
      name: "Content security policy: allowlisted script resources",
      description:
        "Checks for overly permissive script-src directives in Content Security Policy headers that allow too many external script sources",
      type: "passive",
      tags: ["csp", "security-headers", "script-src", "supply-chain", "attack-surface"],
      severities: [Severity.LOW, Severity.MEDIUM],
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
