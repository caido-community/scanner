import { defineCheck, done, Severity } from "engine";

import { keyStrategy } from "../../utils";

export default defineCheck<unknown>(({ step }) => {
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

    const cspHeader = response.getHeader("content-security-policy");

    // Check if CSP header is missing
    if (!cspHeader || cspHeader.length === 0) {
      const finding = {
        name: "Content security policy: not enforced",
        description: `The application does not include a Content Security Policy (CSP) header. Without CSP, the application is vulnerable to Cross-Site Scripting (XSS) attacks, data injection attacks, and other code injection vulnerabilities.

**Missing Header:** \`Content-Security-Policy\`

**Impact:** 
- XSS attacks can execute malicious scripts
- Data injection attacks can inject unauthorized content
- Clickjacking attacks can embed the application in malicious frames

**Recommendation:** Implement a Content Security Policy header with appropriate directives to restrict resource loading and prevent code injection attacks.`,
        severity: Severity.HIGH,
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
      id: "csp-not-enforced",
      name: "Content security policy: not enforced",
      description:
        "Checks for the absence of Content Security Policy headers, which leaves applications vulnerable to XSS and code injection attacks",
      type: "passive",
      tags: ["csp", "security-headers", "xss", "injection"],
      severities: [Severity.HIGH],
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
