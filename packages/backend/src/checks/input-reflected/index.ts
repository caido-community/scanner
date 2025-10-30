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

const BENIGN_VALUES = new Set([
  "true",
  "false",
  "null",
  "undefined",
  "yes",
  "no",
  "on",
  "off",
  "1",
  "0",
]);

const INTERNAL_PARAM_PATTERNS = [
  /^_x_/i, // Slack internal params like _x_gantry, _x_num_retries
  /^fp$/i, // fingerprint param
  /^_.*_$/i, // params wrapped in underscores
];

const isBenignReflection = (param: {
  name: string;
  value: string;
}): boolean => {
  // Ignore single character values (especially numbers like "0")
  if (param.value.length <= 1) {
    return true;
  }

  // Ignore common boolean/null values
  if (BENIGN_VALUES.has(param.value.toLowerCase())) {
    return true;
  }

  // Ignore internal/telemetry parameter names
  if (INTERNAL_PARAM_PATTERNS.some((pattern) => pattern.test(param.name))) {
    return true;
  }

  return false;
};

export default defineCheck<Record<never, never>>(({ step }) => {
  step("detectReflections", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const allReflected = extractReflectedParameters(context);

    // Filter out benign reflections
    const reflected = allReflected
      .filter((param) => !isBenignReflection(param))
      .map((param) => ({
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
