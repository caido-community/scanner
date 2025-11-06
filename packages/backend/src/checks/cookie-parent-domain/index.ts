import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { getSetCookieHeaders, keyStrategy } from "../../utils";

const normalizeHost = (host: string): string => host.toLowerCase();

const normalizeDomain = (domain: string): string =>
  domain.replace(/^\./, "").toLowerCase();

const isParentDomain = (requestHost: string, cookieDomain: string): boolean => {
  if (cookieDomain.length === 0) {
    return false;
  }
  const normalizedDomain = normalizeDomain(cookieDomain);
  const normalizedHost = normalizeHost(requestHost);

  if (normalizedDomain === normalizedHost) {
    return false;
  }

  return normalizedHost.endsWith(`.${normalizedDomain}`);
};

export default defineCheck(({ step }) => {
  step("detectParentDomainCookies", (state, context) => {
    const { response, request } = context.target;
    if (!response) {
      return done({ state });
    }

    const cookies = getSetCookieHeaders(response);
    if (cookies.length === 0) {
      return done({ state });
    }

    const risky = cookies.filter((cookie) => {
      if (cookie.domain === undefined) {
        return false;
      }
      return isParentDomain(request.getHost(), cookie.domain);
    });

    if (risky.length === 0) {
      return done({ state });
    }

    const details = risky
      .map((cookie) => {
        const domain = cookie.domain ?? "";
        return `- Cookie \`${cookie.key}\` is scoped to parent domain \`${domain}\``;
      })
      .join("\n");

    const description = [
      "The response sets cookies scoped to a parent domain, making them accessible to sibling subdomains.",
      "",
      details,
      "",
      "This broad scope can enable session fixation or data leakage across applications hosted on the same parent domain.",
      "**Recommendation:** Scope cookies to the most specific host required (e.g., `Domain=app.example.com`).",
    ].join("\n");

    return done({
      state,
      findings: [
        {
          name: "Cookie scoped to parent domain",
          description,
          severity: Severity.MEDIUM,
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
      id: "cookie-parent-domain",
      name: "Cookie scoped to parent domain",
      description:
        "Detects Set-Cookie headers that scope cookies to parent domains, exposing them to sibling subdomains.",
      type: "passive",
      tags: [Tags.COOKIES, Tags.SECURITY_HEADERS],
      severities: [Severity.MEDIUM],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: () => true,
  };
});
