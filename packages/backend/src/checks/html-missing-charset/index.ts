import { type Response } from "caido:utils";
import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils";

const META_CHARSET_REGEX = /<meta\s+[^>]*charset\s*=\s*["']?\s*([^"'>\s]+)/gi;
const META_HTTP_EQUIV_REGEX =
  /<meta\s+[^>]*http-equiv\s*=\s*["']content-type["'][^>]*content\s*=\s*["'][^"']*charset\s*=\s*([^"';\s]+)/gi;

const extractHeaderCharset = (
  contentType: string | undefined,
): string | undefined => {
  if (contentType === undefined || contentType.length === 0) {
    return undefined;
  }
  const match = contentType.match(/charset\s*=\s*([^;\s]+)/i);
  return match?.[1]?.trim() ?? undefined;
};

const extractMetaCharsets = (body: string): Set<string> => {
  const results = new Set<string>();
  for (const match of body.matchAll(META_CHARSET_REGEX)) {
    const charset = match[1]?.trim();
    if (charset !== undefined && charset.length > 0) {
      results.add(charset);
    }
  }

  for (const match of body.matchAll(META_HTTP_EQUIV_REGEX)) {
    const charset = match[1]?.trim();
    if (charset !== undefined && charset.length > 0) {
      results.add(charset);
    }
  }

  return results;
};

const isHtmlResponse = (response: Response | undefined) => {
  if (response === undefined) return false;
  const header = response.getHeader("content-type")?.[0] ?? "";
  return header.toLowerCase().includes("text/html");
};

export default defineCheck(({ step }) => {
  step("detectMissingCharset", (state, context) => {
    const { response, request } = context.target;
    if (response === undefined) {
      return done({ state });
    }

    if (!isHtmlResponse(response)) {
      return done({ state });
    }

    const headerCharset = extractHeaderCharset(
      response.getHeader("content-type")?.[0],
    );

    if (headerCharset !== undefined && headerCharset.length > 0) {
      return done({ state });
    }

    const body = response.getBody()?.toText() ?? "";
    const metaCharsets =
      body.length > 0 ? extractMetaCharsets(body) : new Set();

    if (metaCharsets.size > 0) {
      return done({ state });
    }

    const description = [
      "The HTML response does not declare a character encoding in the `Content-Type` header or via a `<meta charset>` tag.",
      "",
      "Browsers may guess the encoding, which can revive certain cross-site scripting payloads or cause data corruption.",
      "",
      '**Recommendation:** Define a charset explicitly, such as `Content-Type: text/html; charset=UTF-8`, and include `<meta charset="utf-8">` early in the document.',
    ].join("\n");

    return done({
      state,
      findings: [
        {
          name: "HTML does not specify charset",
          description,
          severity: Severity.LOW,
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
      id: "html-missing-charset",
      name: "HTML missing explicit charset",
      description:
        "Detects HTML responses that do not specify a character encoding in either the Content-Type header or meta tags.",
      type: "passive",
      tags: [Tags.SECURITY_HEADERS, Tags.INPUT_VALIDATION],
      severities: [Severity.LOW],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: () => true,
  };
});
