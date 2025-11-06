import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { extractParameters, type Parameter } from "../../utils";
import { keyStrategy } from "../../utils/key";

const MIN_LENGTH = 16;
const BASE64_REGEX =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/;

const looksLikeBase64 = (value: string): boolean => {
  if (value.length < MIN_LENGTH) {
    return false;
  }

  if (value.length % 4 !== 0) {
    return false;
  }

  return BASE64_REGEX.test(value);
};

const describeParameter = (param: Parameter): string => {
  return `- Parameter \`${param.name}\` from ${param.source} appears to contain Base64 encoded data`;
};

export default defineCheck(({ step }) => {
  step("detectBase64", (state, context) => {
    const params = extractParameters(context);
    if (params.length === 0) {
      return done({ state });
    }

    const matches = params.filter((param) => looksLikeBase64(param.value));
    if (matches.length === 0) {
      return done({ state });
    }

    const details = matches.map(describeParameter).join("\n");

    const description = [
      "One or more parameters look like Base64-encoded data, which can hide sensitive information or payloads from cursory inspection.",
      "",
      details,
      "",
      "**Recommendation:** Review whether Base64 encoding is required. Consider alternative transport mechanisms (cookies, headers) or encrypt sensitive data.",
    ].join("\n");

    return done({
      state,
      findings: [
        {
          name: "Base64 encoded data in parameter",
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
      id: "base64-parameter",
      name: "Base64 encoded data in parameter",
      description:
        "Detects parameters that appear to contain Base64-encoded values.",
      type: "passive",
      tags: [Tags.SENSITIVE_DATA, Tags.INPUT_VALIDATION],
      severities: [Severity.LOW],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: () => true,
  };
});
