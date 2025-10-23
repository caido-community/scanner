import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils";

type FlaggedParam = {
  name: string;
  valueLength: number;
  context: "body" | "header";
};

const PASSWORD_KEYWORDS = [
  "password",
  "passwd",
  "passcode",
  "passphrase",
  "passwrd",
  "pwd",
];

const QUERY_PARAM_REGEX = /[?&]([^&?#"'<>\s=]+)=([^&?#"'<>\s]*)/g;

const sanitize = (value: string): string => {
  return value
    .toLowerCase()
    .replace(/\[|\]/g, "")
    .replace(/[.\-_]/g, "");
};

const decodeValue = (value: string): string => {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
};

const isPasswordIndicator = (value: string): boolean => {
  const normalized = sanitize(value);
  return PASSWORD_KEYWORDS.some((keyword) => normalized.includes(keyword));
};

const extractPasswordParams = (
  text: string,
  context: FlaggedParam["context"],
): FlaggedParam[] => {
  const flagged: FlaggedParam[] = [];

  for (const match of text.matchAll(QUERY_PARAM_REGEX)) {
    const paramName = match[1];
    const rawValue = match[2];

    if (paramName === undefined || rawValue === undefined) {
      continue;
    }

    const decodedValue = decodeValue(rawValue);

    if (isPasswordIndicator(paramName) || isPasswordIndicator(decodedValue)) {
      flagged.push({
        name: paramName,
        valueLength: decodedValue.length,
        context,
      });
    }
  }

  return flagged;
};

const buildDescription = (parameters: FlaggedParam[]): string => {
  const details = parameters
    .map((param) => {
      const lengthText =
        param.valueLength === 0
          ? "empty value"
          : param.valueLength === 1
            ? "1 character"
            : `${param.valueLength} characters`;
      const contextText =
        param.context === "body" ? "response body" : "Location header";

      return `- Parameter \`${param.name}\` appears in the ${contextText} with password-like content (${lengthText}).`;
    })
    .join("\n");

  return [
    "The response exposes a URL query parameter containing password-like data.",
    "",
    details,
    "",
    "Passwords must never be returned to the client. Remove password material from responses and ensure sensitive data is only transmitted during authentication over secure channels.",
  ].join("\n");
};

export default defineCheck<Record<never, never>>(({ step }) => {
  step("inspectResponse", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const flaggedParams: FlaggedParam[] = [];

    const bodyText = response.getBody()?.toText();
    if (bodyText !== undefined && bodyText.length > 0) {
      flaggedParams.push(...extractPasswordParams(bodyText, "body"));
    }

    const locationHeader = response.getHeader("location");
    if (locationHeader !== undefined) {
      for (const headerValue of locationHeader) {
        if (headerValue === undefined || headerValue.length === 0) {
          continue;
        }
        flaggedParams.push(...extractPasswordParams(headerValue, "header"));
      }
    }

    if (flaggedParams.length === 0) {
      return done({ state });
    }

    return done({
      state,
      findings: [
        {
          name: "Password returned in URL query string",
          description: buildDescription(flaggedParams),
          severity: Severity.HIGH,
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
      id: "password-returned-in-url",
      name: "Password returned in URL query string",
      description:
        "Detects responses that include URLs containing password parameters in the query string.",
      type: "passive",
      tags: [Tags.PASSWORD, Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.HIGH],
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
