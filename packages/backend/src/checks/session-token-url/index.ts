import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils";

type FlaggedParam = {
  name: string;
  valueLength: number;
  source: "body" | "header";
};

const TOKEN_KEYWORDS = [
  "token",
  "session",
  "sid",
  "auth",
  "jwt",
  "sso",
  "ticket",
];

const QUERY_PARAM_REGEX = /[?&]([^&?#"'<>=\s]+)=([^&?#"'<>\s]*)/g;

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

const isTokenIndicator = (value: string): boolean => {
  const normalized = sanitize(value);
  return TOKEN_KEYWORDS.some((keyword) => normalized.includes(keyword));
};

const extractTokenParams = (
  text: string,
  source: FlaggedParam["source"],
): FlaggedParam[] => {
  const flagged: FlaggedParam[] = [];

  for (const match of text.matchAll(QUERY_PARAM_REGEX)) {
    const paramName = match[1];
    const paramValue = match[2];

    if (paramName === undefined || paramValue === undefined) {
      continue;
    }

    const decodedValue = decodeValue(paramValue);

    if (isTokenIndicator(paramName) || isTokenIndicator(decodedValue)) {
      flagged.push({
        name: paramName,
        valueLength: decodedValue.length,
        source,
      });
    }
  }

  return flagged;
};

const buildDescription = (params: FlaggedParam[]): string => {
  const details = params
    .map((param) => {
      const lengthText =
        param.valueLength === 0
          ? "empty value"
          : param.valueLength === 1
            ? "1 character"
            : `${param.valueLength} characters`;
      const sourceText =
        param.source === "header" ? "Location header" : "response body";
      return `- Parameter \`${param.name}\` appears in the ${sourceText} with session token-like content (${lengthText}).`;
    })
    .join("\n");

  return [
    "The response exposes session tokens within a URL.",
    "",
    details,
    "",
    "Session tokens must not be transmitted in URLs because they leak via logs, referrers, and browser history. Move tokens into cookies or authorization headers and ensure they are sent only over HTTPS.",
  ].join("\n");
};

export default defineCheck<Record<never, never>>(({ step }) => {
  step("inspectResponse", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const flagged: FlaggedParam[] = [];

    const body = response.getBody()?.toText();
    if (body !== undefined && body.length > 0) {
      flagged.push(...extractTokenParams(body, "body"));
    }

    const locationHeaders = response.getHeader("location");
    if (locationHeaders !== undefined) {
      for (const headerValue of locationHeaders) {
        if (headerValue === undefined || headerValue.length === 0) {
          continue;
        }
        flagged.push(...extractTokenParams(headerValue, "header"));
      }
    }

    if (flagged.length === 0) {
      return done({ state });
    }

    return done({
      state,
      findings: [
        {
          name: "Session token disclosed in URL",
          description: buildDescription(flagged),
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
      id: "session-token-url",
      name: "Session token disclosed in URL",
      description:
        "Detects responses that leak session or authentication tokens via URLs.",
      type: "passive",
      tags: [Tags.SECURITY_HEADERS, Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.HIGH],
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
