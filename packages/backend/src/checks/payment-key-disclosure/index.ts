import { defineRegexCheck, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";
import { whenTextResponse } from "../../utils/when";

export default defineRegexCheck({
  id: "payment-key-disclosure",
  name: "Payment Key Disclosed",
  description:
    "Detects Square payment API keys in HTTP responses that could allow unauthorized transactions",
  tags: [Tags.SECRET],
  severity: Severity.CRITICAL,
  patterns: [/\bsq0atp-[A-Za-z0-9_-]{22}\b/],
  dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  when: whenTextResponse,
  toFinding: (matches) => ({
    name: "Payment Key Disclosed",
    description: `Payment service API keys detected in the response:\n${matches.map((m) => "- `" + m + "`").join("\n")}`,
  }),
});
