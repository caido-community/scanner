import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils";

const hasProtectiveDirectives = (cacheControl: string | undefined): boolean => {
  if (cacheControl === undefined || cacheControl.length === 0) {
    return false;
  }
  const normalized = cacheControl.toLowerCase();
  return (
    normalized.includes("no-store") ||
    normalized.includes("no-cache") ||
    normalized.includes("private") ||
    normalized.includes("must-revalidate") ||
    normalized.includes("max-age=0") ||
    normalized.includes("s-maxage=0")
  );
};

const isExplicitlyPublic = (cacheControl: string | undefined): boolean => {
  if (cacheControl === undefined || cacheControl.length === 0) {
    return false;
  }
  return cacheControl.toLowerCase().includes("public");
};

const hasPragmaNoCache = (pragma: string | undefined): boolean => {
  if (pragma === undefined || pragma.length === 0) {
    return false;
  }
  return pragma.toLowerCase().includes("no-cache");
};

export default defineCheck(({ step }) => {
  step("detectCacheableHttpsResponse", (state, context) => {
    const { request, response } = context.target;

    if (!response || !request.getTls()) {
      return done({ state });
    }

    const cacheControlHeader = response.getHeader("cache-control")?.[0];
    const pragmaHeader = response.getHeader("pragma")?.[0];

    const hasProtection =
      hasProtectiveDirectives(cacheControlHeader) ||
      hasPragmaNoCache(pragmaHeader);

    if (hasProtection) {
      return done({ state });
    }

    const isCacheable =
      cacheControlHeader === undefined ||
      isExplicitlyPublic(cacheControlHeader);

    if (!isCacheable) {
      return done({ state });
    }

    const description = [
      "A response delivered over HTTPS appears cacheable by shared intermediaries.",
      "",
      `**Cache-Control:** \`${cacheControlHeader ?? "<not set>"}\``,
      `**Pragma:** \`${pragmaHeader ?? "<not set>"}\``,
      "",
      "Sensitive HTTPS responses should include `Cache-Control: no-store` (or similar directives) to prevent storage by proxies or browsers.",
    ].join("\n");

    return done({
      state,
      findings: [
        {
          name: "Cacheable HTTPS response",
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
      id: "cacheable-https-response",
      name: "Cacheable HTTPS response",
      description:
        "Identifies HTTPS responses missing cache-control directives that prevent caching.",
      type: "passive",
      tags: [Tags.CACHE, Tags.SECURE],
      severities: [Severity.MEDIUM],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: () => true,
  };
});
