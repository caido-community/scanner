import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

const parseMaxAge = (headerValue: string): number | undefined => {
  const match = headerValue.match(/max-age\s*=\s*(\d+)/i);
  if (match === null) {
    return undefined;
  }
  return Number.parseInt(match[1] ?? "", 10);
};

const hasIncludeSubdomains = (headerValue: string): boolean => {
  return /\bincludeSubDomains\b/i.test(headerValue);
};

const buildDescription = (details: {
  reason: "missing" | "insufficientMaxAge" | "noIncludeSubdomains";
  maxAge?: number;
  includeSubdomains?: boolean;
}): string => {
  const messages: string[] = [];

  if (details.reason === "missing") {
    messages.push(
      "The response was served over HTTPS but did not include the `Strict-Transport-Security` header.",
    );
  } else if (details.reason === "insufficientMaxAge") {
    messages.push(
      `The response sets \`Strict-Transport-Security\` with \`max-age=${details.maxAge ?? 0}\`, which is below the recommended minimum of 31536000 seconds (one year).`,
    );
  } else if (details.reason === "noIncludeSubdomains") {
    messages.push(
      "The `Strict-Transport-Security` header is missing the `includeSubDomains` directive. Subdomains may remain accessible over HTTP.",
    );
  }

  messages.push(
    "",
    "Missing or weak HSTS allows browsers to downgrade back to HTTP, enabling man-in-the-middle and cookie hijacking attacks.",
    "",
    "Set `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` on all HTTPS responses.",
  );

  return messages.join("\n");
};

export default defineCheck<Record<never, never>>(({ step }) => {
  step("checkHstsHeader", (state, context) => {
    const { request, response } = context.target;

    if (request.getTls() !== true || response === undefined) {
      return done({ state });
    }

    const hstsHeader = response.getHeader("strict-transport-security");

    if (hstsHeader === undefined || hstsHeader.length === 0) {
      return done({
        state,
        findings: [
          {
            name: "Strict-Transport-Security header missing",
            description: buildDescription({ reason: "missing" }),
            severity: Severity.MEDIUM,
            correlation: {
              requestID: request.getId(),
              locations: [],
            },
          },
        ],
      });
    }

    const headerValue = hstsHeader[0] ?? "";
    const maxAge = parseMaxAge(headerValue);

    if (maxAge === undefined || Number.isNaN(maxAge) || maxAge < 31536000) {
      return done({
        state,
        findings: [
          {
            name: "Strict-Transport-Security max-age too low",
            description: buildDescription({
              reason: "insufficientMaxAge",
              maxAge,
            }),
            severity: Severity.LOW,
            correlation: {
              requestID: request.getId(),
              locations: [],
            },
          },
        ],
      });
    }

    if (!hasIncludeSubdomains(headerValue)) {
      return done({
        state,
        findings: [
          {
            name: "Strict-Transport-Security missing includeSubDomains",
            description: buildDescription({
              reason: "noIncludeSubdomains",
              includeSubdomains: false,
            }),
            severity: Severity.LOW,
            correlation: {
              requestID: request.getId(),
              locations: [],
            },
          },
        ],
      });
    }

    return done({ state });
  });

  return {
    metadata: {
      id: "hsts-not-enforced",
      name: "Strict Transport Security not enforced",
      description:
        "Detects HTTPS responses that omit the Strict-Transport-Security header or configure it insecurely.",
      type: "passive",
      tags: [Tags.SECURITY_HEADERS],
      severities: [Severity.LOW, Severity.MEDIUM],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().build(),
    when: (target) => target.response !== undefined,
  };
});
