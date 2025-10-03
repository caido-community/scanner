import { defineCheck, done, Severity } from "engine";

import { CSPParser } from "../../parsers/csp";
import { keyStrategy } from "../../utils";

export default defineCheck<unknown>(({ step }) => {
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

    // Find form-action directive
    const formActionDirective = parsedCsp.directives.find(
      (d) => d.name === "form-action"
    );

    const findings = [];

    // Check if form-action directive is missing
    if (!formActionDirective) {
      findings.push({
        name: "Content security policy: allows form hijacking",
        description: `The Content Security Policy is missing the form-action directive, which can lead to form hijacking attacks.

**CSP Header:** \`${cspValue}\`

**Missing Directive:** \`form-action\`

**Impact:** 
- Forms can be submitted to malicious endpoints
- CSRF attacks can redirect form submissions
- Data exfiltration through form redirection
- Unauthorized data submission to external domains

**Recommendation:** Add a form-action directive to restrict where forms can be submitted. Use 'self' to allow only same-origin submissions, or specify trusted domains.`,
        severity: Severity.MEDIUM,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      });
    } else {
      // Check for overly permissive form-action values
      const formActionValues = formActionDirective.values;

      // Check for wildcard
      if (formActionValues.includes("*")) {
        findings.push({
          name: "Content security policy: allows form hijacking",
          description: `The Content Security Policy allows forms to be submitted to any destination with wildcard (*), which can lead to form hijacking attacks.

**CSP Header:** \`${cspValue}\`

**Directive:** \`form-action\`

**Unsafe Values:** \`*\`

**Impact:** 
- Forms can be submitted to any malicious endpoint
- Complete bypass of form submission restrictions
- Data exfiltration through form redirection

**Recommendation:** Replace wildcard (*) with specific trusted domains or use 'self' for same-origin submissions only.`,
          severity: Severity.HIGH,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        });
      }

      // Check for data: and blob: sources
      const unsafeSources = formActionValues.filter(
        (value) => value.startsWith("data:") || value.startsWith("blob:")
      );

      if (unsafeSources.length > 0) {
        findings.push({
          name: "Content security policy: allows form hijacking",
          description: `The Content Security Policy allows forms to be submitted to data: and blob: sources, which can lead to form hijacking attacks.

**CSP Header:** \`${cspValue}\`

**Directive:** \`form-action\`

**Unsafe Sources:** \`${unsafeSources.join(", ")}\`

**Impact:** 
- Forms can be submitted to data URLs
- Data exfiltration through malicious form actions
- Bypass of form submission restrictions

**Recommendation:** Remove data: and blob: sources from form-action unless absolutely necessary for legitimate use cases.`,
          severity: Severity.MEDIUM,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        });
      }

      // Check for HTTP sources without HTTPS
      const httpSources = formActionValues.filter(
        (value) => value.startsWith("http:") && !value.startsWith("https:")
      );

      if (httpSources.length > 0) {
        findings.push({
          name: "Content security policy: allows form hijacking",
          description: `The Content Security Policy allows forms to be submitted to HTTP sources, which can be intercepted and modified.

**CSP Header:** \`${cspValue}\`

**Directive:** \`form-action\`

**HTTP Sources:** \`${httpSources.join(", ")}\`

**Impact:** 
- HTTP form submissions can be intercepted by attackers
- Man-in-the-middle attacks can modify form data
- Insecure transmission of sensitive form data

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
      id: "csp-form-hijacking",
      name: "Content security policy: allows form hijacking",
      description:
        "Checks for missing or overly permissive form-action directives in Content Security Policy headers, which can lead to form hijacking attacks",
      type: "passive",
      tags: ["csp", "security-headers", "form-hijacking", "csrf", "form-action"],
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
