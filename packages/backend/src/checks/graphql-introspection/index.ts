import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

type FindingDetails = {
  type: "__schema" | "__type";
};

const detectFromJson = (body: string): FindingDetails | undefined => {
  try {
    const parsed = JSON.parse(body) as Record<string, unknown>;
    if (parsed === null || typeof parsed !== "object") {
      return undefined;
    }

    const data = parsed.data;
    if (data === null || data === undefined) {
      return undefined;
    }

    if (typeof data === "object") {
      if ("__schema" in (data as Record<string, unknown>)) {
        return { type: "__schema" };
      }

      if ("__type" in (data as Record<string, unknown>)) {
        return { type: "__type" };
      }
    }
  } catch {
    // Ignore JSON parse errors
  }

  return undefined;
};

const FALLBACK_REGEX = /"__schema"\s*:/;

const buildDescription = (details: FindingDetails): string => {
  const subject = details.type === "__schema" ? "`__schema`" : "`__type`";

  return [
    "The GraphQL endpoint responded to an introspection query.",
    "",
    `The response includes the ${subject} field, indicating that schema introspection is enabled.`,
    "",
    "Exposed schema metadata can significantly aid attackers in enumerating operations and crafting targeted attacks. Disable introspection on production environments or protect the endpoint behind authentication.",
  ].join("\n");
};

export default defineCheck<Record<never, never>>(({ step }) => {
  step("detectIntrospection", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const bodyText = response.getBody()?.toText();
    if (bodyText === undefined || bodyText.length === 0) {
      return done({ state });
    }

    const details = detectFromJson(bodyText);
    if (details !== undefined) {
      return done({
        state,
        findings: [
          {
            name: "GraphQL introspection enabled",
            description: buildDescription(details),
            severity: Severity.MEDIUM,
            correlation: {
              requestID: context.target.request.getId(),
              locations: [],
            },
          },
        ],
      });
    }

    if (FALLBACK_REGEX.test(bodyText)) {
      return done({
        state,
        findings: [
          {
            name: "GraphQL introspection enabled",
            description: buildDescription({ type: "__schema" }),
            severity: Severity.MEDIUM,
            correlation: {
              requestID: context.target.request.getId(),
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
      id: "graphql-introspection-enabled",
      name: "GraphQL introspection enabled",
      description:
        "Detects GraphQL responses that disclose schema metadata via introspection.",
      type: "passive",
      tags: [Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.MEDIUM],
      aggressivity: {
        minRequests: 0,
        maxRequests: 0,
      },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPath().build(),
    when: (target) => target.response !== undefined,
  };
});
