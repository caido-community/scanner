import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { extractReflectedParameters } from "../../utils";
import { keyStrategy } from "../../utils/key";

const buildDescription = (
  reflectedParams: Array<{ name: string; valueLength: number; source: string }>,
): string => {
  const details = reflectedParams
    .map((param) => {
      const lengthText =
        param.valueLength === 0
          ? "empty value"
          : param.valueLength === 1
            ? "1 character"
            : `${param.valueLength} characters`;
      return `- Parameter \`${param.name}\` from ${param.source} is reflected (${lengthText}).`;
    })
    .join("\n");

  return [
    "User-supplied input is reflected in the response without sanitisation.",
    "",
    details,
    "",
    "Reflected input can lead to cross-site scripting or other response-splitting attacks when combined with payloads that manipulate the HTML/JavaScript context. Ensure untrusted data is escaped or encoded appropriately before being rendered.",
  ].join("\n");
};

export default defineCheck<Record<never, never>>(({ step }) => {
  step("detectReflections", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const reflected = extractReflectedParameters(context).map((param) => ({
      name: param.name,
      valueLength: param.value.length,
      source: param.source,
    }));

    if (reflected.length === 0) {
      return done({ state });
    }

    return done({
      state,
      findings: [
        {
          name: "Input reflected in response",
          description: buildDescription(reflected),
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
      id: "input-reflected",
      name: "Input reflected in response",
      description:
        "Detects user-supplied values that are echoed back in the HTTP response.",
      type: "passive",
      tags: [Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.LOW],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPath().withQuery().build(),
    when: (target) => target.response !== undefined,
  };
});
