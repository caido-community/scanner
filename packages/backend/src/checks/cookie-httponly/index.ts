import { defineCheck, done, Severity } from "engine";

import { getSetCookieHeaders, keyStrategy } from "../../utils";
import { Tags } from "../tags";

export default defineCheck<unknown>(({ step }) => {
  step("checkCookieHttpOnly", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const cookies = getSetCookieHeaders(response);

    if (cookies.length === 0) {
      return done({ state });
    }

    const findings = [];

    for (const cookie of cookies) {
      if (!cookie.isHttpOnly) {
        findings.push({
          name: "Cookie without HttpOnly flag set",
          description: `The cookie '${cookie.key}' is set without the HttpOnly flag. This makes the cookie accessible to JavaScript, which can lead to XSS attacks where malicious scripts can steal the cookie value.

**Cookie:** \`${cookie.key}\`
**Cookie Value:** \`${cookie.value}\`

**Recommendation:** Add the HttpOnly flag to prevent client-side JavaScript access to the cookie.`,
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
      id: "cookie-httponly",
      name: "Cookie HttpOnly Flag Check",
      description:
        "Checks for cookies that are set without the HttpOnly flag, which can be accessed by JavaScript and lead to XSS attacks",
      type: "passive",
      tags: [Tags.COOKIES, Tags.HTTPONLY, Tags.XSS, Tags.SECURITY_HEADERS],
      severities: [Severity.LOW],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: (context) => context.response !== undefined,
  };
});
