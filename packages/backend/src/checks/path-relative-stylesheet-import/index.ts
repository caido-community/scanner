import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

type FindingEntry = {
  type: "link" | "import";
  value: string;
};

const LINK_STYLESHEET_REGEX = /<link\b[^>]*rel=["']?stylesheet["']?[^>]*>/gi;
const HREF_REGEX = /href=(["'])([^"']+)\1/i;
const IMPORT_REGEX = /@import\s+(?:url\()?["']?([^"')\s]+)["']?(?:\))?/gi;

const isRelativePath = (value: string): boolean => {
  const trimmed = value.trim().toLowerCase();

  if (
    trimmed.startsWith("http://") ||
    trimmed.startsWith("https://") ||
    trimmed.startsWith("//") ||
    trimmed.startsWith("/") ||
    trimmed.startsWith("data:") ||
    trimmed.startsWith("javascript:") ||
    trimmed.startsWith("#")
  ) {
    return false;
  }

  return true;
};

const collectFindings = (body: string): FindingEntry[] => {
  const findings: FindingEntry[] = [];

  for (const tag of body.matchAll(LINK_STYLESHEET_REGEX)) {
    const element = tag[0];
    if (element === undefined) {
      continue;
    }

    const hrefMatch = element.match(HREF_REGEX);
    const hrefValue = hrefMatch?.[2];
    if (hrefValue !== undefined && isRelativePath(hrefValue)) {
      findings.push({ type: "link", value: hrefValue });
    }
  }

  for (const match of body.matchAll(IMPORT_REGEX)) {
    const importValue = match[1];
    if (importValue !== undefined && isRelativePath(importValue)) {
      findings.push({ type: "import", value: importValue });
    }
  }

  return findings;
};

const buildDescription = (entries: FindingEntry[]): string => {
  const details = entries
    .map((entry) => {
      const description =
        entry.type === "link" ? "link href attribute" : "@import rule";
      return `- Relative path \`${entry.value}\` used in ${description}.`;
    })
    .join("\n");

  return [
    "The response references a stylesheet using a path-relative URL.",
    "",
    details,
    "",
    "Path-relative imports are prone to being resolved against attacker-controlled paths (for example when serving content from nested routes or via user-supplied directories). Use absolute paths or fully qualified URLs for stylesheet references.",
  ].join("\n");
};

export default defineCheck<Record<never, never>>(({ step }) => {
  step("detectRelativeStylesheets", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const body = response.getBody()?.toText();
    if (body === undefined || body.length === 0) {
      return done({ state });
    }

    const findings = collectFindings(body);
    if (findings.length === 0) {
      return done({ state });
    }

    return done({
      state,
      findings: [
        {
          name: "Path-relative stylesheet import",
          description: buildDescription(findings),
          severity: Severity.LOW,
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
      id: "path-relative-stylesheet-import",
      name: "Path-relative stylesheet import",
      description:
        "Detects stylesheet references that rely on path-relative URLs, which can break isolation boundaries when directories are attacker-controlled.",
      type: "passive",
      tags: [Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.LOW],
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
