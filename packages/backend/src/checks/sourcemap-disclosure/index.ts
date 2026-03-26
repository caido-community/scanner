import { defineCheckV2, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

const isJavaScriptResponse = (
  contentType: string | undefined,
  path: string,
): boolean => {
  if (contentType !== undefined && contentType.includes("javascript")) {
    return true;
  }

  return path.endsWith(".js");
};

export default defineCheckV2({
  id: "sourcemap-disclosure",
  name: "Source Map Disclosed",
  description:
    "Detects JavaScript responses that expose source map references, potentially revealing original source code",
  type: "passive",
  tags: [Tags.JAVASCRIPT, Tags.INFORMATION_DISCLOSURE],
  severities: [Severity.MEDIUM],
  aggressivity: {
    minRequests: 0,
    maxRequests: 0,
  },
  dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  when: (target) => {
    if (target.response === undefined) return false;
    if (target.response.getCode() !== 200) return false;

    const contentType = target.response.getHeader("content-type")?.[0];
    const path = target.request.getPath();

    return isJavaScriptResponse(contentType, path);
  },

  execute(ctx) {
    const sourceMapHeader =
      ctx.target.header("sourcemap") ?? ctx.target.header("x-sourcemap");

    if (sourceMapHeader !== undefined) {
      ctx.finding({
        name: "Source Map Disclosed via Header",
        description: `The response includes a source map header pointing to \`${sourceMapHeader}\`. This may allow attackers to reconstruct the original source code.`,
        severity: Severity.MEDIUM,
      });
      return Promise.resolve();
    }

    const bodyText = ctx.target.bodyText();
    if (bodyText === undefined) return Promise.resolve();

    if (bodyText.includes("//# sourceMappingURL=")) {
      ctx.finding({
        name: "Source Map Disclosed via Comment",
        description:
          "The JavaScript response contains a `sourceMappingURL` comment directive. This may allow attackers to reconstruct the original source code.",
        severity: Severity.MEDIUM,
      });
    }

    return Promise.resolve();
  },
});
