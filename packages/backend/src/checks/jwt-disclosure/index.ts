import { defineRegexCheck, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";
import { whenTextResponse } from "../../utils/when";

export default defineRegexCheck({
  id: "jwt-disclosure",
  name: "JWT Disclosed",
  description:
    "Detects JSON Web Tokens in HTTP response bodies that may leak authentication or session data",
  tags: [Tags.SECRET, Tags.CRYPTOGRAPHY],
  severity: Severity.INFO,
  patterns: [
    /\beyJ[A-Za-z0-9_-]{10,4096}\.eyJ[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,4096}\b/,
  ],
  dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  when: whenTextResponse,
  toFinding: (matches) => ({
    name: "JWT Disclosed",
    description: `JSON Web Tokens detected in the response:\n${matches.map((m) => "- `" + m + "`").join("\n")}`,
  }),
});
