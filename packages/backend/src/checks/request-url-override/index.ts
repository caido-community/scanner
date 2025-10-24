import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

const OVERRIDE_HEADER_NAMES = [
  "x-original-url",
  "x-rewrite-url",
  "x-forwarded-url",
  "x-forwarded-uri",
  "x-forwarded-prefix",
  "x-forwarded-path",
  "x-forwarded-proto",
  "x-forwarded-host",
  "forwarded",
];

const sanitizeValue = (value: string | undefined): string => {
  if (value === undefined || value.length === 0) {
    return "(empty)";
  }

  return value.length > 120 ? `${value.slice(0, 117)}...` : value;
};

type Match = {
  header: string;
  value: string | undefined;
  direction: "request" | "response";
};

const collectMatches = (
  headers: Record<string, string[]>,
  direction: Match["direction"],
): Match[] => {
  const matches: Match[] = [];
  for (const [name, values] of Object.entries(headers)) {
    const lowerName = name.toLowerCase();
    if (OVERRIDE_HEADER_NAMES.includes(lowerName)) {
      matches.push({ header: lowerName, value: values?.[0], direction });
    }
  }
  return matches;
};

const buildDescription = (matches: Match[]): string => {
  const details = matches
    .map((match) => {
      const source = match.direction === "request" ? "request" : "response";
      return `- Header \`${match.header}\` observed in ${source} with value \`${sanitizeValue(match.value)}\`.`;
    })
    .join("\n");

  return [
    "Proxy URL-override headers were observed in the traffic.",
    "",
    details,
    "",
    "When upstream proxies or application servers honour these headers, attackers can rewrite the target URL to bypass routing restrictions or access privileged endpoints. Strip untrusted override headers at the edge or configure the proxy to reject them.",
  ].join("\n");
};

export default defineCheck<Record<never, never>>(({ step }) => {
  step("inspectHeaders", (state, context) => {
    const { request, response } = context.target;

    const matches: Match[] = [];

    matches.push(...collectMatches(request.getHeaders(), "request"));

    if (response !== undefined) {
      matches.push(...collectMatches(response.getHeaders(), "response"));
    }

    if (matches.length === 0) {
      return done({ state });
    }

    return done({
      state,
      findings: [
        {
          name: "Request URL override headers observed",
          description: buildDescription(matches),
          severity: Severity.MEDIUM,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        },
      ],
    });
  });

  return {
    metadata: {
      id: "request-url-override",
      name: "Request URL override headers",
      description:
        "Detects HTTP traffic containing proxy override headers (e.g., X-Original-URL, X-Forwarded-Host).",
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
