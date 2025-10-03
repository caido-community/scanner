import { defineCheck, done, Severity } from "engine";

import { CSPParser } from "../../parsers/csp";
import { keyStrategy } from "../../utils";

export default defineCheck<unknown>(({ step }) => {
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

    // Check for malformed syntax
    const findings = [];

    // Check for empty directives (malformed)
    for (const directive of parsedCsp.directives) {
      if (directive.name === "" || directive.name.trim() === "") {
        findings.push({
          name: "Content security policy: malformed syntax",
          description: `The Content Security Policy header contains malformed syntax with empty directive names.

**CSP Header:** \`${cspValue}\`

**Issue:** Empty directive name detected

**Impact:** Malformed CSP headers may be ignored by browsers, leaving the application vulnerable to XSS and code injection attacks.

**Recommendation:** Fix the CSP syntax by ensuring all directives have valid names and proper formatting.`,
          severity: Severity.MEDIUM,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        });
        break;
      }
    }

    // Check for invalid directive names (common typos)
    const validDirectives = [
      "default-src",
      "script-src",
      "style-src",
      "img-src",
      "font-src",
      "connect-src",
      "media-src",
      "object-src",
      "child-src",
      "frame-src",
      "worker-src",
      "manifest-src",
      "form-action",
      "frame-ancestors",
      "base-uri",
      "upgrade-insecure-requests",
      "block-all-mixed-content",
      "require-sri-for",
      "sandbox",
      "report-uri",
      "report-to",
    ];

    for (const directive of parsedCsp.directives) {
      if (!validDirectives.includes(directive.name)) {
        findings.push({
          name: "Content security policy: malformed syntax",
          description: `The Content Security Policy header contains an invalid directive name.

**CSP Header:** \`${cspValue}\`

**Invalid Directive:** \`${directive.name}\`

**Impact:** Invalid directive names may be ignored by browsers, reducing the effectiveness of the CSP.

**Recommendation:** Use valid CSP directive names. Common valid directives include: default-src, script-src, style-src, img-src, etc.`,
          severity: Severity.MEDIUM,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        });
        break;
      }
    }

    // Check for duplicate directives
    const directiveNames = parsedCsp.directives.map((d) => d.name);
    const duplicateDirectives = directiveNames.filter(
      (name, index) => directiveNames.indexOf(name) !== index,
    );

    if (duplicateDirectives.length > 0) {
      findings.push({
        name: "Content security policy: malformed syntax",
        description: `The Content Security Policy header contains duplicate directives.

**CSP Header:** \`${cspValue}\`

**Duplicate Directives:** \`${duplicateDirectives.join(", ")}\`

**Impact:** Duplicate directives may cause unexpected behavior as browsers typically use the last occurrence.

**Recommendation:** Remove duplicate directives and consolidate their values into a single directive.`,
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
      id: "csp-malformed-syntax",
      name: "Content security policy: malformed syntax",
      description:
        "Checks for malformed Content Security Policy headers that may be ignored by browsers",
      type: "passive",
      tags: ["csp", "security-headers", "syntax", "validation"],
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
