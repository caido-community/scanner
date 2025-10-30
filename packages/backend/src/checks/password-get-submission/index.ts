import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils";

type FindingParam = {
  name: string;
  length: number;
};

const PASSWORD_KEYWORDS = [
  "password",
  "passwd",
  "passcode",
  "passphrase",
  "passwrd",
  "pwd",
];

const sanitizeName = (name: string): string => {
  const lower = name.toLowerCase();
  return lower.replace(/\[|\]/g, "").replace(/[.\-_]/g, "");
};

const isPasswordParameter = (name: string): boolean => {
  const lowerName = name.toLowerCase();

  if (lowerName.includes("password")) {
    return true;
  }

  const normalized = sanitizeName(name);
  return PASSWORD_KEYWORDS.some((keyword) => normalized.includes(keyword));
};

const buildFindingDescription = (params: FindingParam[]): string => {
  const details = params
    .map((param) => {
      const lengthText =
        param.length === 0
          ? "empty value"
          : param.length === 1
            ? "1 character"
            : `${param.length} characters`;
      return `- Query parameter \`${param.name}\` appears to contain a password submitted via GET (${lengthText}).`;
    })
    .join("\n");

  return [
    "A password-like parameter was detected in the URL query string of a `GET` request.",
    "",
    details,
    "",
    "Transmitting credentials in the URL exposes them to browser history, intermediary logs, and referrer headers. Switch to a POST-based submission and ensure the connection is protected with HTTPS.",
  ].join("\n");
};

export default defineCheck<unknown>(({ step }) => {
  step("inspectQueryParameters", (state, context) => {
    const request = context.target.request;

    if (request.getMethod().toUpperCase() !== "GET") {
      return done({ state });
    }

    const query = request.getQuery();
    if (query === undefined || query.length === 0) {
      return done({ state });
    }

    const urlParams = new URLSearchParams(query);
    const passwordParams: FindingParam[] = [];

    for (const [name, value] of urlParams.entries()) {
      if (value === undefined) {
        continue;
      }

      if (isPasswordParameter(name)) {
        passwordParams.push({ name, length: value.length });
      }
    }

    if (passwordParams.length === 0) {
      return done({ state });
    }

    return done({
      state,
      findings: [
        {
          name: "Password submitted using GET method",
          description: buildFindingDescription(passwordParams),
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
      id: "password-get-submission",
      name: "Password submitted using GET method",
      description:
        "Detects GET requests where password-like parameters are transmitted in the URL query string.",
      type: "passive",
      tags: [Tags.PASSWORD, Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.HIGH],
      aggressivity: {
        minRequests: 0,
        maxRequests: 0,
      },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPath().withQueryKeys().build(),
    when: (target) => target.request.getMethod().toUpperCase() === "GET",
  };
});
