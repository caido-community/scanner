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
  low: 2,
  medium: 5,
  high: 10,
} as const;

const COOKIE_LIMITS = {
  low: 1,
  medium: 2,
  high: 4,
} as const;

const HEADER_LIMITS = {
  low: 1,
  medium: 1,
  high: 2,
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
  id: "input-stored",
  name: "Input returned in response (stored)",
  description:
    "Detects stored input by injecting a unique marker into query parameters, cookie values, and common headers, then sending a follow-up request without the marker to check whether the old value is reflected.",
  type: "active",
  tags: [Tags.INPUT_VALIDATION],
  severities: [Severity.INFO],
  aggressivity: {
    minRequests: 2,
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

      const poisonResult = await ctx.send(vector.createSpec(marker));
      if (Result.isErr(poisonResult)) {
        continue;
      }

      const verifyResult = await ctx.send(ctx.target.request.toSpec());
      if (Result.isErr(verifyResult)) {
        continue;
      }

      const verifyBody = verifyResult.value.response.getBody()?.toText();
      if (verifyBody === undefined) {
        continue;
      }

      if (!verifyBody.includes(marker)) {
        continue;
      }

      ctx.finding({
        name: `Input returned in response (stored) via ${vector.kind} '${vector.name}'`,
        severity: Severity.INFO,
        description: `The application appears to store attacker-controlled input from the ${formatInputVector(vector)}. After sending a request with an injected marker, a follow-up request without the marker still returned the old value in the response body.\n\nThis is informational, but stored reflection can be relevant for stored XSS, cache poisoning, log injection, and other persistence-related issues depending on where the value ends up and how it is used.`,
        artifacts: {
          title: "Detection details",
          items: [
            `Input: ${formatInputVector(vector)}`,
            `Marker: ${marker}`,
            `Poison request ID: ${poisonResult.value.request.getId()}`,
          ],
        },
        request: verifyResult.value.request,
      });
      return;
    }
  },
});
