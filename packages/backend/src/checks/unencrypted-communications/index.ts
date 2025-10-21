import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils";

export default defineCheck(({ step }) => {
  step("detectUnencrypted", (state, context) => {
    const { request } = context.target;

    if (request.getTls()) {
      return done({ state });
    }

    const host = request.getHost();
    const description = [
      "The request was observed over an unencrypted HTTP connection.",
      "",
      `**Host:** \`${host}\``,
      "",
      "Sensitive information transmitted over HTTP can be intercepted or modified by attackers on the network.",
      "",
      "**Recommendation:** Serve this content over HTTPS and enforce HSTS to ensure clients always use TLS.",
    ].join("\n");

    return done({
      state,
      findings: [
        {
          name: "Unencrypted HTTP communication",
          description,
          severity: Severity.HIGH,
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
      id: "unencrypted-communications",
      name: "Unencrypted communications",
      description:
        "Alerts when HTTP requests are observed without TLS protection",
      type: "passive",
      tags: [Tags.TLS, Tags.SECURE],
      severities: [Severity.HIGH],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().build(),
    when: () => true,
  };
});
