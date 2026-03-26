import { defineCheckV2, Result, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

const WORDPRESS_INDICATORS = [
  /<meta\s+name=["']generator["']\s+content=["']WordPress/i,
  /<h1[^>]*>\s*WordPress\s*<\/h1>/i,
  /wp-includes/i,
  /wp-admin/i,
];

const MIN_INDICATORS = 2;

function isValidWordPressReadme(bodyText: string): boolean {
  if (!bodyText.toLowerCase().includes("wordpress")) {
    return false;
  }

  let matchCount = 0;
  for (const pattern of WORDPRESS_INDICATORS) {
    if (pattern.test(bodyText)) {
      matchCount += 1;
      if (matchCount >= MIN_INDICATORS) {
        return true;
      }
    }
  }

  return false;
}

export default defineCheckV2({
  id: "wordpress-readme",
  name: "WordPress Readme Exposed",
  description:
    "Detects publicly accessible WordPress readme.html files that may reveal version information",
  type: "active",
  tags: [Tags.INFRASTRUCTURE, Tags.ATTACK_SURFACE],
  severities: [Severity.INFO],
  aggressivity: {
    minRequests: 1,
    maxRequests: 1,
  },
  dedupeKey: keyStrategy().withHost().withPort().build(),

  async execute(ctx) {
    const readmePath = "/readme.html";
    const spec = ctx.target.request.toSpec();

    spec.setPath(readmePath);
    spec.setMethod("GET");
    spec.setQuery("");
    spec.setBody("");

    const result = await ctx.send(spec);
    if (Result.isErr(result)) return;

    const { request, response } = result.value;
    if (response.getCode() !== 200) return;

    const body = response.getBody();
    if (body === undefined) return;

    const bodyText = body.toText();
    if (!isValidWordPressReadme(bodyText)) return;

    ctx.finding({
      name: "WordPress Readme Exposed",
      description: `A WordPress \`readme.html\` file is publicly accessible at \`${readmePath}\`. This file may reveal the WordPress version and other platform details useful for targeted attacks.`,
      severity: Severity.INFO,
      request,
    });
  },
});
