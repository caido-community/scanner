import { defineRegexCheck, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";
import { whenTextResponse } from "../../utils/when";

export default defineRegexCheck({
  id: "gitlab-token-disclosure",
  name: "GitLab Token Disclosed",
  description:
    "Detects GitLab personal access tokens, pipeline trigger tokens, and runner registration tokens in HTTP responses",
  tags: [Tags.SECRET, Tags.CICD],
  severity: Severity.HIGH,
  patterns: [
    /\bglpat-[A-Za-z0-9_-]{20,}\b/,
    /\bglptt-[A-Za-z0-9_-]{20,}\b/,
    /\bglrt-[A-Za-z0-9_-]{20,}\b/,
  ],
  dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  when: whenTextResponse,
  toFinding: (matches) => ({
    name: "GitLab Token Disclosed",
    description: `GitLab tokens detected in the response:\n${matches.map((m) => "- `" + m + "`").join("\n")}`,
  }),
});
