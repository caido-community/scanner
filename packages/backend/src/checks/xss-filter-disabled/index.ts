import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils";

const isFilterDisabled = (values: Array<string> | undefined): boolean => {
  if (!values) return false;

  return values.some((value) => {
    const normalized = value.trim().toLowerCase();
    if (normalized === "0") return true;
    if (normalized.startsWith("0;")) return true;
    return normalized.includes("mode=0");
  });
};

export default defineCheck(({ step }) => {
  step("detectDisabledFilter", (state, context) => {
    const { response, request } = context.target;
    if (!response) {
      return done({ state });
    }

    const headerValues = response.getHeader("x-xss-protection");
    if (!isFilterDisabled(headerValues)) {
      return done({ state });
    }

    const description = [
      "The response sets the `X-XSS-Protection` header to `0`, disabling the legacy browser XSS filter.",
      "",
      `**Header value:** \`${headerValues?.join(", ") ?? ""}\``,
      "",
      "**Note:** This is generally the CORRECT and RECOMMENDED configuration.",
      "- Modern browsers have removed support for `X-XSS-Protection`",
      "- Setting it to `0` prevents bugs in legacy XSS filters",
      "- OWASP and security experts recommend either `0` or omitting the header entirely",
      "",
      "**Only consider this an issue if:**",
      "- You need to support very old browsers (IE8-11, old Chrome/Safari)",
      "- Your application has specific legacy compatibility requirements",
      "",
      "For more information, see: https://owasp.org/www-project-secure-headers/#x-xss-protection",
    ].join("\n");

    return done({
      state,
      findings: [
        {
          name: "Browser XSS filter disabled",
          description,
          severity: Severity.INFO,
          correlation: {
            requestID: request.getId(),
            locations: [],
          },
        },
      ],
    });
  });

  return {
    metadata: {
      id: "xss-filter-disabled",
      name: "Browser XSS filter disabled",
      description:
        "Detects responses that disable the legacy XSS filter using X-XSS-Protection: 0 (Note: This is generally correct modern practice).",
      type: "passive",
      tags: [Tags.SECURITY_HEADERS, Tags.XSS],
      severities: [Severity.INFO],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: () => true,
  };
});
