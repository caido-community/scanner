import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { getSetCookieHeaders } from "../../utils";
import { keyStrategy } from "../../utils/key";

const PASSWORD_KEYWORDS = [
  "password",
  "passwd",
  "passcode",
  "passphrase",
  "passwrd",
  "pwd",
];

type FlaggedCookie = {
  name: string;
  valueLength: number;
  httpOnly: boolean;
  secure: boolean;
};

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

const isPasswordIndicator = (text: string): boolean => {
  const normalized = sanitize(text);
  return PASSWORD_KEYWORDS.some((keyword) => normalized.includes(keyword));
};

const collectFlaggedCookies = (
  cookies: ReturnType<typeof getSetCookieHeaders>,
): FlaggedCookie[] => {
  const flagged: FlaggedCookie[] = [];

  for (const cookie of cookies) {
    const cookieName = cookie.key;
    const cookieValue = cookie.value;

    if (cookieName === undefined || cookieValue === undefined) {
      continue;
    }

    const decodedValue = decodeValue(cookieValue);

    if (isPasswordIndicator(cookieName) || isPasswordIndicator(decodedValue)) {
      flagged.push({
        name: cookieName,
        valueLength: decodedValue.length,
        httpOnly: cookie.isHttpOnly,
        secure: cookie.isSecure,
      });
    }
  }

  return flagged;
};

const buildDescription = (cookies: FlaggedCookie[]): string => {
  const details = cookies
    .map((cookie) => {
      const lengthText =
        cookie.valueLength === 0
          ? "empty value"
          : cookie.valueLength === 1
            ? "1 character"
            : `${cookie.valueLength} characters`;

      const flags: string[] = [];
      flags.push(cookie.httpOnly ? "HttpOnly" : "no HttpOnly");
      flags.push(cookie.secure ? "Secure" : "no Secure");

      return `- Cookie \`${cookie.name}\` appears to store a password-like value (${lengthText}; ${flags.join(
        ", ",
      )}).`;
    })
    .join("\n");

  return [
    "The application sets cookies that appear to contain password values.",
    "",
    details,
    "",
    "Password material must never be stored client-side. Use short-lived session identifiers or cryptographic tokens instead and keep raw credentials on the server.",
  ].join("\n");
};

export default defineCheck<Record<never, never>>(({ step }) => {
  step("inspectCookies", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const cookies = getSetCookieHeaders(response);
    if (cookies.length === 0) {
      return done({ state });
    }

    const flaggedCookies = collectFlaggedCookies(cookies);
    if (flaggedCookies.length === 0) {
      return done({ state });
    }

    return done({
      state,
      findings: [
        {
          name: "Password value stored in cookie",
          description: buildDescription(flaggedCookies),
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
      id: "password-in-cookie",
      name: "Password value stored in cookie",
      description:
        "Detects Set-Cookie headers that store password-like values, indicating insecure credential handling.",
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
