import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils";

type DetectedToken = {
  location: string;
  name?: string;
  value: string;
};

const PARAMETER_PATTERNS = [
  /^(?:jsessionid)$/i,
  /^(?:phpsessid)$/i,
  /^(?:sessionid|session_id|sessid|sessionkey|session_key)$/i,
  /^(?:sid)$/i,
  /^(?:auth_token|authtoken)$/i,
  /^(?:token|access_token|id_token|bearer)$/i,
];

const PATH_TOKEN_REGEX = /;(?:(?:j|php)?sessionid|sid|token)=([^;/?#]+)/gi;

const MIN_TOKEN_LENGTH = 8;

const maskValue = (value: string) => {
  if (value.length <= 8) {
    return value;
  }

  return `${value.slice(0, 4)}...${value.slice(-4)}`;
};

const isSensitiveParameter = (name: string, value: string): boolean => {
  if (value.length < MIN_TOKEN_LENGTH) {
    return false;
  }

  return PARAMETER_PATTERNS.some((pattern) => pattern.test(name));
};

export default defineCheck(({ step }) => {
  step("detectSessionTokens", (state, context) => {
    const tokens: DetectedToken[] = [];
    const { request } = context.target;

    const query = request.getQuery() ?? "";
    if (query !== "") {
      const params = new URLSearchParams(query);
      for (const [name, value] of params.entries()) {
        if (isSensitiveParameter(name, value)) {
          tokens.push({
            location: "query",
            name,
            value: maskValue(value),
          });
        }
      }
    }

    const path = request.getPath();
    if (path !== undefined && path.length > 0) {
      for (const match of path.matchAll(PATH_TOKEN_REGEX)) {
        const rawValue = match[1] ?? "";
        if (rawValue.length >= MIN_TOKEN_LENGTH) {
          tokens.push({
            location: "path",
            value: maskValue(rawValue),
          });
        }
      }
    }

    if (tokens.length === 0) {
      return done({ state });
    }

    const details = tokens
      .map((token) => {
        if (token.name !== undefined && token.name.length > 0) {
          return `- Parameter \`${token.name}\` in ${token.location} contains value \`${token.value}\``;
        }
        return `- ${token.location} contains session token value \`${token.value}\``;
      })
      .join("\n");

    const description = [
      "The request appears to include session credentials in the URL.",
      "Session identifiers transmitted via the URL may be leaked through logs, browser history, referrer headers, or intermediary caches.",
      "",
      details,
      "",
      "**Recommendation:** Move session identifiers to secure cookies or headers and avoid propagating them through the URL.",
    ].join("\n");

    return done({
      state,
      findings: [
        {
          name: "Session token disclosed in URL",
          description,
          severity: Severity.HIGH,
          correlation: {
            requestID: request.getId(),
            locations: [],
          },
        },
      ],
    });
  });

  return {
    metadata: {
      id: "session-token-in-url",
      name: "Session token in URL",
      description:
        "Detects session identifiers or tokens transmitted via the request URL",
      type: "passive",
      tags: [
        Tags.SENSITIVE_DATA,
        Tags.SESSION_MANAGEMENT,
        Tags.SECURITY_HEADERS,
      ],
      severities: [Severity.HIGH],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy()
      .withMethod()
      .withHost()
      .withPort()
      .withPath()
      .withQuery()
      .build(),
    when: () => true,
  };
});
