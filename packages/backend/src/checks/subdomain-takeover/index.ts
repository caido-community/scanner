import { defineCheckV2, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

const TAKEOVER_FINGERPRINTS = [
  "There isn't a GitHub Pages site here",
  "NoSuchBucket",
  "The specified bucket does not exist",
  "Sorry, this shop is currently unavailable",
  "Fastly error: unknown domain",
  "There is no app configured at that hostname",
  "Repository not found",
];

export default defineCheckV2({
  id: "subdomain-takeover",
  name: "Subdomain Takeover",
  description:
    "Detects potential subdomain takeover vulnerabilities by identifying error pages from unclaimed cloud services",
  type: "passive",
  tags: [Tags.INFRASTRUCTURE, Tags.ATTACK_SURFACE],
  severities: [Severity.HIGH],
  aggressivity: { minRequests: 0, maxRequests: 0 },
  dedupeKey: keyStrategy().withHost().withPort().build(),
  when: (target) => {
    if (target.response === undefined) return false;
    if (target.response.getCode() !== 404) return false;
    const body = target.response.getBody();
    if (body === undefined) return false;
    return body.toText().length <= 10_000;
  },

  execute(ctx): Promise<void> {
    const body = ctx.target.bodyText();
    if (body === undefined) return Promise.resolve();

    const matched: string[] = [];
    for (const fingerprint of TAKEOVER_FINGERPRINTS) {
      if (body.includes(fingerprint)) {
        matched.push(fingerprint);
      }
    }

    if (matched.length === 0) return Promise.resolve();

    ctx.finding({
      name: "Subdomain Takeover",
      severity: Severity.HIGH,
      description: `Potential subdomain takeover detected. The following fingerprints were found in the response:\n${matched.map((m) => "- `" + m + "`").join("\n")}`,
    });

    return Promise.resolve();
  },
});
