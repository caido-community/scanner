import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils";

const splitContentTypes = (values: Array<string>): string[] => {
  const tokens: string[] = [];

  for (const raw of values) {
    const parts = raw
      .split(",")
      .map((part) => part.trim())
      .filter((part) => part.length > 0);

    tokens.push(...parts);
  }

  return tokens;
};

const buildDescription = (types: string[]): string => {
  const list = types.map((type) => `- \`${type}\``).join("\n");

  return [
    "The response specifies multiple `Content-Type` values, making it unclear which media type the browser should honor.",
    "",
    "Conflicting content types can be abused to trigger MIME confusion in browsers or caching layers, potentially enabling content sniffing or script execution in contexts where it should be blocked.",
    "",
    "Observed header values:",
    list,
    "",
    "Return only a single, unambiguous `Content-Type` header for each response.",
  ].join("\n");
};

export default defineCheck<Record<never, never>>(({ step }) => {
  step("detectMultipleContentTypes", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const contentTypeHeader = response.getHeader("content-type");
    if (contentTypeHeader === undefined || contentTypeHeader.length === 0) {
      return done({ state });
    }

    const contentTypes = splitContentTypes(contentTypeHeader);
    const uniqueTypes = Array.from(
      new Set(contentTypes.map((value) => value.toLowerCase())),
    );

    if (uniqueTypes.length <= 1) {
      return done({ state });
    }

    const originalOrder: string[] = [];
    for (const value of contentTypes) {
      const lower = value.toLowerCase();
      if (!originalOrder.some((existing) => existing.toLowerCase() === lower)) {
        originalOrder.push(value);
      }
    }

    return done({
      state,
      findings: [
        {
          name: "Multiple Content-Type headers detected",
          description: buildDescription(originalOrder),
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
      id: "multiple-content-types",
      name: "Multiple Content-Type headers",
      description:
        "Detects responses that declare more than one Content-Type value, which can lead to MIME confusion vulnerabilities.",
      type: "passive",
      tags: [Tags.INFORMATION_DISCLOSURE, Tags.SECURITY_HEADERS],
      severities: [Severity.MEDIUM],
      aggressivity: {
        minRequests: 0,
        maxRequests: 0,
      },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPath().withQuery().build(),
    when: (target) => target.response !== undefined,
  };
});
