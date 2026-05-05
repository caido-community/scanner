import { defineCheck, done, Severity } from "engine";

import { getSetCookieHeaders, keyStrategy } from "../../utils";
import { Tags } from "../tags";

export default defineCheck<unknown>(({ step }) => {
  step("checkCookieSecure", (state, context) => {
    const { response, request } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    // Only check for secure flag on TLS connections
    if (!request.getTls()) {
      return done({ state });
    }

    const cookies = getSetCookieHeaders(response);

    if (cookies.length === 0) {
      return done({ state });
    }

    const findings = [];

    for (const cookie of cookies) {
      if (!cookie.isSecure) {
        findings.push({
          name: "TLS cookie without Secure flag set",
          description: `The cookie '${cookie.key}' is set over a TLS connection without the Secure flag. This makes the cookie vulnerable to being transmitted over unencrypted connections if the application is accessed via HTTP.

**Cookie:** \`${cookie.key}\`
**Cookie Value:** \`${cookie.value}\`
**Connection:** TLS (HTTPS)

**Recommendation:** Add the Secure flag to ensure the cookie is only transmitted over encrypted connections.`,
          severity: Severity.MEDIUM,
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
      id: "cookie-secure",
      name: "Cookie Secure Flag Check",
      description:
        "Checks for cookies set over TLS connections without the Secure flag, which can lead to cookie transmission over unencrypted connections",
      type: "passive",
      tags: [Tags.COOKIES, Tags.SECURE, Tags.TLS, Tags.SECURITY_HEADERS],
      severities: [Severity.MEDIUM],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: (context) =>
      context.response !== undefined && context.request.getTls(),
  };
});
