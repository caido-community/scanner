import { defineRegexCheck, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";
import { whenTextResponse } from "../../utils/when";

export default defineRegexCheck({
  id: "firebase-config-disclosure",
  name: "Firebase Config Disclosed",
  description:
    "Detects Firebase database URLs and API key configurations in HTTP responses",
  tags: [Tags.SECRET, Tags.CLOUD],
  severity: Severity.INFO,
  patterns: [
    /[a-zA-Z0-9_-]+\.firebaseio\.com/,
    /apiKey["']?\s{0,5}[:=]\s{0,5}["']?AIza[0-9A-Za-z_-]{35}/,
  ],
  dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  when: whenTextResponse,
  toFinding: (matches) => ({
    name: "Firebase Config Disclosed",
    description: `Firebase configuration detected in the response:\n${matches.map((m) => "- `" + m + "`").join("\n")}`,
  }),
});
