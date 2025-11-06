import { type Response } from "caido:utils";
import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils";

const RECOGNIZED_CHARSETS = new Set(
  [
    "utf-8",
    "utf8",
    "utf-16",
    "utf-16le",
    "utf-16be",
    "iso-8859-1",
    "iso-8859-2",
    "iso-8859-3",
    "iso-8859-4",
    "iso-8859-5",
    "iso-8859-6",
    "iso-8859-7",
    "iso-8859-8",
    "iso-8859-8-i",
    "iso-8859-9",
    "iso-8859-10",
    "iso-8859-13",
    "iso-8859-14",
    "iso-8859-15",
    "iso-8859-16",
    "windows-1250",
    "windows-1251",
    "windows-1252",
    "windows-1253",
    "windows-1254",
    "windows-1255",
    "windows-1256",
    "windows-1257",
    "windows-1258",
    "windows-874",
    "shift_jis",
    "euc-jp",
    "euc-kr",
    "gbk",
    "gb2312",
    "gb18030",
    "big5",
    "koi8-r",
    "koi8-u",
    "macintosh",
    "iso-2022-jp",
  ].map((charset) => charset.toLowerCase()),
);

const META_CHARSET_REGEX = /<meta\s+[^>]*charset\s*=\s*["']?\s*([^"'>\s]+)/gi;
const META_HTTP_EQUIV_REGEX =
  /<meta\s+[^>]*http-equiv\s*=\s*["']content-type["'][^>]*content\s*=\s*["'][^"']*charset\s*=\s*([^"';\s]+)/gi;

const normalizeCharset = (charset: string | undefined): string | undefined => {
  if (charset === undefined || charset.length === 0) {
    return undefined;
  }
  return charset.trim().toLowerCase();
};

const isHtmlResponse = (response: Response | undefined) => {
  if (response === undefined) return false;
  const header = response.getHeader("content-type")?.[0] ?? "";
  return header.toLowerCase().includes("text/html");
};

const extractHeaderCharset = (contentType: string | undefined) => {
  if (contentType === undefined || contentType.length === 0) {
    return undefined;
  }
  const match = contentType.match(/charset\s*=\s*([^;\s]+)/i);
  return normalizeCharset(match?.[1]);
};

const extractMetaCharsets = (body: string): Set<string> => {
  const results = new Set<string>();
  for (const match of body.matchAll(META_CHARSET_REGEX)) {
    const charset = normalizeCharset(match[1]);
    if (charset !== undefined) {
      results.add(charset);
    }
  }

  for (const match of body.matchAll(META_HTTP_EQUIV_REGEX)) {
    const charset = normalizeCharset(match[1]);
    if (charset !== undefined) {
      results.add(charset);
    }
  }

  return results;
};

export default defineCheck(({ step }) => {
  step("detectUnrecognizedCharset", (state, context) => {
    const { response, request } = context.target;
    if (!response) {
      return done({ state });
    }

    if (!isHtmlResponse(response)) {
      return done({ state });
    }

    const findings = [];

    const headerValue = response.getHeader("content-type")?.[0];
    const headerCharset = extractHeaderCharset(headerValue);
    if (
      headerCharset !== undefined &&
      !RECOGNIZED_CHARSETS.has(headerCharset)
    ) {
      findings.push(
        `Content-Type header declares unrecognized charset \`${headerCharset}\`.`,
      );
    }

    const bodyText = response.getBody()?.toText() ?? "";
    if (bodyText.length > 0) {
      const metaCharsets = extractMetaCharsets(bodyText);
      for (const charset of metaCharsets) {
        if (!RECOGNIZED_CHARSETS.has(charset)) {
          findings.push(
            `HTML document declares unrecognized charset \`${charset}\` in meta tag.`,
          );
        }
      }
    }

    if (findings.length === 0) {
      return done({ state });
    }

    const description = [
      "The HTML page declares a character encoding that is not recognized by modern browsers.",
      "",
      findings.map((item) => `- ${item}`).join("\n"),
      "",
      "**Security impact:** Browsers may fall back to a different encoding, which can reintroduce certain XSS vectors or cause content misinterpretation.",
      "**Recommendation:** Use a standard charset such as `UTF-8` in both the `Content-Type` header and HTML `<meta charset>` tag.",
    ].join("\n");

    return done({
      state,
      findings: [
        {
          name: "HTML uses unrecognized charset",
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
      id: "html-unrecognized-charset",
      name: "HTML uses unrecognized charset",
      description:
        "Detects HTML responses that declare an unrecognized character encoding in headers or meta tags.",
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
