import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

const DID_YOU_MEAN_REGEX = /did you mean/i;

const hasSuggestion = (body: string): boolean => {
  try {
    const parsed = JSON.parse(body) as Record<string, unknown>;
    if (parsed === null || typeof parsed !== "object") {
      return false;
    }

    const errors = parsed.errors;
    if (!Array.isArray(errors)) {
      return false;
    }

    for (const error of errors) {
      if (error !== null && typeof error === "object") {
        const message = (error as Record<string, unknown>).message;
        if (typeof message === "string" && DID_YOU_MEAN_REGEX.test(message)) {
          return true;
        }

        const extensions = (error as Record<string, unknown>).extensions;
        if (
          extensions !== null &&
          typeof extensions === "object" &&
          "didYouMean" in extensions
        ) {
          return true;
        }
      }
    }
  } catch {
    // Ignore invalid JSON
  }

  return DID_YOU_MEAN_REGEX.test(body);
};

const description = [
  "The GraphQL endpoint returns field suggestions in error responses.",
  "",
  "When introspection is disabled but suggestions remain active, attackers can still enumerate field names by triggering typos and reviewing the `Did you mean ...` hints.",
  "",
  "Disable GraphQL query suggestions in production environments to reduce information leakage.",
].join("\n");

export default defineCheck<Record<never, never>>(({ step }) => {
  step("detectSuggestions", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const body = response.getBody()?.toText();
    if (body === undefined || body.length === 0) {
      return done({ state });
    }

    if (!hasSuggestion(body)) {
      return done({ state });
    }

    return done({
      state,
      findings: [
        {
          name: "GraphQL suggestions enabled",
          description,
          severity: Severity.LOW,
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
      id: "graphql-suggestions-enabled",
      name: "GraphQL suggestions enabled",
      description:
        'Detects GraphQL error responses that disclose field suggestions ("Did you mean ...").',
      type: "passive",
      tags: [Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.LOW],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPath().build(),
    when: (target) => target.response !== undefined,
  };
});
