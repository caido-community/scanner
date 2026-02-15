import { defineCheckV2, Result, type ScanTarget, Severity } from "engine";

import { Tags } from "../../../types";
import { keyStrategy } from "../../../utils/key";
import {
  createCookieInputVectors,
  createHeaderInputVectors,
  createQueryInputVectors,
  formatInputVector,
} from "../inputs";
import { createMarker } from "../marker";

const QUERY_LIMITS = {
  low: 3,
  medium: 8,
  high: 15,
} as const;

const COOKIE_LIMITS = {
  low: 1,
  medium: 3,
  high: 5,
} as const;

const HEADER_LIMITS = {
  low: 1,
  medium: 2,
  high: 3,
} as const;

const hasResponseBody = (target: ScanTarget): boolean => {
  const response = target.response;
  if (response === undefined) {
    return false;
  }

  const body = response.getBody()?.toText();
  return body !== undefined && body !== "";
};

export default defineCheckV2({
  id: "input-reflected",
  name: "Input returned in response (reflected)",
  description:
    "Detects reflected input by injecting unique markers into query parameters, cookie values, and common headers, then checking whether the marker is returned in the response.",
  type: "active",
  tags: [Tags.INPUT_VALIDATION],
  severities: [Severity.INFO],
  aggressivity: {
    minRequests: 1,
    maxRequests: "Infinity",
  },
  dedupeKey: keyStrategy()
    .withMethod()
    .withHost()
    .withPort()
    .withPath()
    .withQueryKeys()
    .build(),
  when: (target) => {
    if (target.request.getMethod().toUpperCase() !== "GET") {
      return false;
    }

    return hasResponseBody(target);
  },
  async execute(ctx) {
    const baselineBody = ctx.target.bodyText();
    if (baselineBody === undefined) {
      return;
    }

    const queryVectors = ctx.limit(createQueryInputVectors(ctx), QUERY_LIMITS);
    const cookieVectors = ctx.limit(
      createCookieInputVectors(ctx.target.request),
      COOKIE_LIMITS,
    );
    const headerVectors = ctx.limit(
      createHeaderInputVectors(ctx.target.request),
      HEADER_LIMITS,
    );

    const vectors = [...queryVectors, ...cookieVectors, ...headerVectors];
    if (vectors.length === 0) {
      return;
    }

    const usedMarkers = new Set<string>();

    for (const vector of vectors) {
      const marker = createMarker({ baselineBody, usedMarkers });

      const result = await ctx.send(vector.createSpec(marker));
      if (Result.isErr(result)) {
        continue;
      }

      const responseBody = result.value.response.getBody()?.toText();
      if (responseBody === undefined) {
        continue;
      }

      if (!responseBody.includes(marker)) {
        continue;
      }

      ctx.finding({
        name: `Input returned in response (reflected) in ${vector.kind} '${vector.name}'`,
        severity: Severity.INFO,
        description: `The application reflects attacker-controlled input from the ${formatInputVector(vector)} in the response body.\n\nThis is informational, but reflection can be a prerequisite for HTML injection, XSS, cache poisoning, or other injection issues depending on how the value is used and encoded.`,
        artifacts: {
          title: "Detection details",
          items: [`Input: ${formatInputVector(vector)}`, `Marker: ${marker}`],
        },
        request: result.value.request,
      });
      return;
    }
  },
});
