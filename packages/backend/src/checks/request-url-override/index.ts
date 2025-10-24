import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

const HEADER_NAMES = ["x-original-url", "x-rewrite-url", "x-forwarded-url"];

const buildDescription = (
  header: string,
  value: string | undefined,
): string => {
  const sanitizedValue =
    value === undefined || value.length === 0 ? "(no value)" : value;
  return [
    `The response includes the \`${header}\` header with value \`${sanitizedValue}\`.`,
    "",
    "Some reverse proxies honour these headers to override the request URL. Attackers can abuse this behaviour to bypass routing controls or access restricted endpoints.",
    "",
    "Ensure upstream proxies strip untrusted URL override headers before forwarding the request to the application server.",
  ].join("\n");
};

export default defineCheck<Record<never, never>>(({ step }) => {
  step("inspectHeaders", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    for (const name of HEADER_NAMES) {
      const headerValues = response.getHeader(name);
      if (headerValues !== undefined && headerValues.length > 0) {
        const first = headerValues[0];
        return done({
          state,
          findings: [
            {
              name: "Request URL override header exposed",
              description: buildDescription(name, first),
              severity: Severity.MEDIUM,
              correlation: {
                requestID: context.target.request.getId(),
                locations: [],
              },
            },
          ],
        });
      }
    }

    return done({ state });
  });

  return {
    metadata: {
      id: "request-url-override",
      name: "Request URL override header exposed",
      description:
        "Detects responses that return proxy override headers such as X-Original-URL or X-Rewrite-URL.",
      type: "passive",
      tags: [Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.MEDIUM],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPath().build(),
    when: (target) => target.response !== undefined,
  };
});
