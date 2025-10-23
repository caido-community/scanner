import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

type MixedContentEntry = {
  attribute: string;
  url: string;
};

const ATTRIBUTE_PATTERN =
  /\b(src|href|data-src|data-href|action)=(["'])http:\/\/([^"']+)\2/gi;
const CSS_URL_PATTERN = /url\((["']?)http:\/\/([^)"']+)\1\)/gi;

const collectMixedContent = (body: string): MixedContentEntry[] => {
  const entries: MixedContentEntry[] = [];

  for (const match of body.matchAll(ATTRIBUTE_PATTERN)) {
    const attribute = match[1];
    const url = match[3];
    if (attribute !== undefined && url !== undefined) {
      entries.push({ attribute, url: `http://${url}` });
    }
  }

  for (const match of body.matchAll(CSS_URL_PATTERN)) {
    const url = match[2];
    if (url !== undefined) {
      entries.push({ attribute: "css-url", url: `http://${url}` });
    }
  }

  return entries;
};

const buildDescription = (entries: MixedContentEntry[]): string => {
  const details = entries
    .map((entry) => {
      const label =
        entry.attribute === "css-url"
          ? "CSS url() declaration"
          : `attribute \`${entry.attribute}\``;
      return `- ${label} loads insecure resource \`${entry.url}\`.`;
    })
    .join("\n");

  return [
    "The HTTPS response includes references to insecure HTTP resources.",
    "",
    details,
    "",
    "Mixed content undermines HTTPS guarantees and allows attackers to tamper with externally loaded scripts, styles, or media. Serve resources over HTTPS or embed them locally.",
  ].join("\n");
};

export default defineCheck<Record<never, never>>(({ step }) => {
  step("detectMixedContent", (state, context) => {
    const { request, response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    if (request.getTls() !== true) {
      return done({ state });
    }

    const body = response.getBody()?.toText();
    if (body === undefined || body.length === 0) {
      return done({ state });
    }

    const entries = collectMixedContent(body);
    if (entries.length === 0) {
      return done({ state });
    }

    return done({
      state,
      findings: [
        {
          name: "Mixed content detected",
          description: buildDescription(entries),
          severity: Severity.MEDIUM,
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
      id: "mixed-content",
      name: "Mixed content",
      description:
        "Detects HTTPS responses that reference insecure HTTP resources.",
      type: "passive",
      tags: [Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.MEDIUM],
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
