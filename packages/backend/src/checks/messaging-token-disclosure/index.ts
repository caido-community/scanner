import { defineRegexCheck, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";
import { whenTextResponse } from "../../utils/when";

export default defineRegexCheck({
  id: "messaging-token-disclosure",
  name: "Messaging Token Disclosed",
  description: "Detects Discord webhook URLs in HTTP responses",
  tags: [Tags.SECRET],
  severity: Severity.HIGH,
  patterns: [
    /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,20}\/[A-Za-z0-9_-]{60,68}/,
  ],
  dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  when: whenTextResponse,
  toFinding: (matches) => ({
    name: "Messaging Token Disclosed",
    description: `Messaging service tokens detected in the response:\n${matches.map((m) => "- `" + m + "`").join("\n")}`,
  }),
});
