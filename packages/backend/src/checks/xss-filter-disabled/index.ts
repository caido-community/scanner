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
      "The response disables the legacy browser XSS filter via the `X-XSS-Protection` header.",
      "",
      `**Header value:** \`${headerValues?.join(", ") ?? ""}\``,
      "",
      "While modern browsers ignore this header, disabling the filter can expose older clients to reflected XSS.",
      "**Recommendation:** Remove the header or set it to `1; mode=block` for legacy compatibility.",
    ].join("\n");

    return done({
      state,
      findings: [
        {
          name: "Browser XSS filter disabled",
          description,
          severity: Severity.LOW,
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
        "Detects responses that disable the legacy XSS filter using the X-XSS-Protection header.",
      type: "passive",
      tags: [Tags.SECURITY_HEADERS, Tags.XSS],
      severities: [Severity.LOW],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: () => true,
  };
});
