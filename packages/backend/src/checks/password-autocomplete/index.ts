import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

type FlaggedField = {
  hasAttribute: boolean;
  attributeValue?: string;
};

const PASSWORD_INPUT_REGEX = /<input\b[^>]*type=(["'])password\1[^>]*>/gi;
const AUTOCOMPLETE_REGEX = /autocomplete=(["'])([^"']+)\1/i;

const isAutocompleteDisabled = (value: string): boolean => {
  const normalized = value.trim().toLowerCase();
  return normalized === "off" || normalized === "new-password";
};

const collectFlaggedFields = (body: string): FlaggedField[] => {
  const fields: FlaggedField[] = [];

  for (const match of body.matchAll(PASSWORD_INPUT_REGEX)) {
    const inputTag = match[0];
    if (inputTag === undefined) {
      continue;
    }

    const autocompleteMatch = inputTag.match(AUTOCOMPLETE_REGEX);
    const autocompleteValue = autocompleteMatch?.[2];

    if (autocompleteValue === undefined) {
      fields.push({ hasAttribute: false });
      continue;
    }

    if (!isAutocompleteDisabled(autocompleteValue)) {
      fields.push({
        hasAttribute: true,
        attributeValue: autocompleteValue,
      });
    }
  }

  return fields;
};

const buildDescription = (fields: FlaggedField[]): string => {
  const details = fields
    .map((field, index) => {
      if (field.hasAttribute) {
        return `- Password input #${index + 1} sets \`autocomplete="${field.attributeValue ?? ""}"\`.`;
      }
      return `- Password input #${index + 1} omits the \`autocomplete\` attribute, allowing browsers to autofill credentials.`;
    })
    .join("\n");

  return [
    "The response contains password fields that permit browser autocomplete.",
    "",
    details,
    "",
    'Autocomplete should be disabled for password inputs using `autocomplete="off"` or `autocomplete="new-password"` to reduce the risk of credential theft on shared machines and shoulder-surfing attacks.',
  ].join("\n");
};

export default defineCheck<Record<never, never>>(({ step }) => {
  step("inspectPasswordInputs", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const body = response.getBody()?.toText();
    if (body === undefined || body.length === 0) {
      return done({ state });
    }

    const flaggedFields = collectFlaggedFields(body);
    if (flaggedFields.length === 0) {
      return done({ state });
    }

    return done({
      state,
      findings: [
        {
          name: "Password field with autocomplete enabled",
          description: buildDescription(flaggedFields),
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
      id: "password-autocomplete",
      name: "Password field with autocomplete enabled",
      description:
        "Detects password inputs that allow browser autocomplete instead of explicitly disabling it.",
      type: "passive",
      tags: [Tags.PASSWORD, Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.LOW],
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
