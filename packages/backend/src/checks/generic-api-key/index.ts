import { defineRegexCheck, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";
import { whenTextResponse } from "../../utils/when";

export default defineRegexCheck({
  id: "generic-api-key",
  name: "Generic API Key Disclosed",
  description:
    "Detects generic API keys, secrets, and access tokens in HTTP responses using common naming patterns",
  tags: [Tags.SECRET],
  severity: Severity.LOW,
  patterns: [
    /(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token)["']?\s{0,5}[:=]\s{0,5}["']([A-Za-z0-9_-]{20,64})["']/i,
  ],
  dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  when: whenTextResponse,
  toFinding: (matches) => ({
    name: "Generic API Key Disclosed",
    description: `Generic API keys or secrets detected in the response:\n${matches.map((m) => "- `" + m + "`").join("\n")}`,
  }),
});
