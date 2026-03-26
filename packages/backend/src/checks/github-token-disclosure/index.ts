import { defineRegexCheck, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";
import { whenTextResponse } from "../../utils/when";

export default defineRegexCheck({
  id: "github-token-disclosure",
  name: "GitHub Token Disclosed",
  description:
    "Detects GitHub personal access tokens, OAuth tokens, and app tokens in HTTP responses",
  tags: [Tags.SECRET, Tags.CICD],
  severity: Severity.HIGH,
  patterns: [
    /\bghp_[A-Za-z0-9]{36,255}\b/,
    /\bgho_[A-Za-z0-9]{36,255}\b/,
    /\bghu_[A-Za-z0-9]{36,255}\b/,
    /\bghs_[A-Za-z0-9]{36,255}\b/,
    /\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b/,
  ],
  dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  when: whenTextResponse,
  toFinding: (matches) => ({
    name: "GitHub Token Disclosed",
    description: `GitHub tokens detected in the response:\n${matches.map((m) => "- `" + m + "`").join("\n")}`,
  }),
});
