import { defineRegexCheck, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";
import { whenTextResponse } from "../../utils/when";

export default defineRegexCheck({
  id: "aws-key-disclosure",
  name: "AWS Key Disclosed",
  description:
    "Detects AWS access key IDs in HTTP responses that could allow unauthorized access to AWS services",
  tags: [Tags.SECRET, Tags.CLOUD],
  severity: Severity.CRITICAL,
  patterns: [
    /\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/,
  ],
  dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  when: whenTextResponse,
  toFinding: (matches) => ({
    name: "AWS Key Disclosed",
    description: `AWS access key IDs detected in the response:\n${matches.map((m) => "- `" + m + "`").join("\n")}`,
  }),
});
