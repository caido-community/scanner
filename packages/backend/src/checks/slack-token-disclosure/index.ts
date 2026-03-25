import { defineRegexCheck, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";
import { whenTextResponse } from "../../utils/when";

export default defineRegexCheck({
  id: "slack-token-disclosure",
  name: "Slack Token Disclosed",
  description:
    "Detects Slack bot tokens, user tokens, and webhook URLs in HTTP responses",
  tags: [Tags.SECRET],
  severity: Severity.HIGH,
  patterns: [
    /\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34}\b/,
    /\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34}\b/,
    /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24}/,
  ],
  dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  when: whenTextResponse,
  toFinding: (matches) => ({
    name: "Slack Token Disclosed",
    description: `Slack tokens or webhook URLs detected in the response:\n${matches.map((m) => "- `" + m + "`").join("\n")}`,
  }),
});
