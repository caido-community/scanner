import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { getSetCookieHeaders, keyStrategy } from "../../utils";

export default defineCheck(({ step }) => {
  step("detectDuplicateCookies", (state, context) => {
    const { response, request } = context.target;

    if (!response) {
      return done({ state });
    }

    const cookies = getSetCookieHeaders(response);
    if (cookies.length === 0) {
      return done({ state });
    }

    const counts = new Map<string, number>();
    for (const cookie of cookies) {
      const key = cookie.key.toLowerCase();
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }

    const duplicates = Array.from(counts.entries()).filter(
      ([, count]) => count > 1,
    );
    if (duplicates.length === 0) {
      return done({ state });
    }

    const details = duplicates
      .map(([name, count]) => `- Cookie \`${name}\` is set ${count} times`)
      .join("\n");

    const description = [
      "The response sets the same cookie name multiple times.",
      "",
      details,
      "",
      "Browsers may choose an arbitrary value, enabling session fixation or inconsistent behaviour.",
      "**Recommendation:** Ensure each cookie name is set only once per response and consolidate attributes if needed.",
    ].join("\n");

    return done({
      state,
      findings: [
        {
          name: "Duplicate cookies set",
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
      id: "duplicate-cookies",
      name: "Duplicate cookies set",
      description:
        "Detects responses that set the same cookie name multiple times.",
      type: "passive",
      tags: [Tags.COOKIES, Tags.SECURITY_HEADERS],
      severities: [Severity.LOW],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: () => true,
  };
});
