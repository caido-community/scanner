import { defineRegexCheck, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";
import { whenTextResponse } from "../../utils/when";

export default defineRegexCheck({
  id: "stripe-key-disclosure",
  name: "Stripe Key Disclosed",
  description:
    "Detects Stripe live secret keys and restricted keys in HTTP responses",
  tags: [Tags.SECRET],
  severity: Severity.CRITICAL,
  patterns: [
    /\bsk_live_[A-Za-z0-9]{24,99}\b/,
    /\brk_live_[A-Za-z0-9]{24,99}\b/,
  ],
  dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  when: whenTextResponse,
  toFinding: (matches) => ({
    name: "Stripe Key Disclosed",
    description: `Stripe live API keys detected in the response:\n${matches.map((m) => "- `" + m + "`").join("\n")}`,
  }),
});
