import { defineRegexCheck, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";
import { whenTextResponse } from "../../utils/when";

export default defineRegexCheck({
  id: "cicd-token-disclosure",
  name: "CI/CD Token Disclosed",
  description:
    "Detects BuildKite and CircleCI tokens in HTTP responses that could allow unauthorized pipeline access",
  tags: [Tags.SECRET, Tags.CICD],
  severity: Severity.HIGH,
  patterns: [
    /\bbkua_[A-Za-z0-9]{40}\b/,
    /(?:circle[_-]?token)\s*[:=]\s*["']?([a-f0-9]{40})/i,
  ],
  dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  when: whenTextResponse,
  toFinding: (matches) => ({
    name: "CI/CD Token Disclosed",
    description: `CI/CD tokens detected in the response:\n${matches.map((m) => "- `" + m + "`").join("\n")}`,
  }),
});
