import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

const detectFromJson = (body: string): boolean => {
  try {
    const parsed = JSON.parse(body) as Record<string, unknown>;
    if (parsed === null || typeof parsed !== "object") {
      return false;
    }

    if (parsed.data !== undefined || parsed.errors !== undefined) {
      if (Array.isArray(parsed.errors)) {
        for (const error of parsed.errors) {
          if (error !== null && typeof error === "object") {
            const message = (error as Record<string, unknown>).message;
            if (typeof message === "string" && /graphql/i.test(message)) {
              return true;
            }

            const extensions = (error as Record<string, unknown>).extensions;
            if (
              extensions !== null &&
              typeof extensions === "object" &&
              typeof (extensions as Record<string, unknown>).code ===
                "string" &&
              /(graphql|validation_failed)/i.test(
                (extensions as Record<string, unknown>).code as string,
              )
            ) {
              return true;
            }
          }
        }
      }

      return true;
    }
  } catch {
    // Ignore parse errors
  }

  return false;
};

const FALLBACK_REGEX = /GraphQL(?:\s+(?:Playground|schema|Error|validation))/i;

const description = [
  "The response appears to originate from a GraphQL endpoint.",
  "",
  "Knowing that GraphQL is in use helps attackers focus enumeration efforts (introspection, brute-forcing operations, etc.).",
  "",
  "Consider restricting access to GraphQL endpoints in production or enforcing strong authentication.",
].join("\n");

export default defineCheck<Record<never, never>>(({ step }) => {
  step("detectGraphqlEndpoint", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const body = response.getBody()?.toText();
    if (body === undefined || body.length === 0) {
      return done({ state });
    }

    if (!detectFromJson(body) && !FALLBACK_REGEX.test(body)) {
      return done({ state });
    }

    return done({
      state,
      findings: [
        {
          name: "GraphQL endpoint detected",
          description,
          severity: Severity.INFO,
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
      id: "graphql-endpoint-found",
      name: "GraphQL endpoint detected",
      description:
        "Identifies responses that indicate the presence of a GraphQL API.",
      type: "passive",
      tags: [Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.INFO],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPath().build(),
    when: (target) => target.response !== undefined,
  };
});
