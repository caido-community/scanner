import { defineRegexCheck, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";
import { whenTextResponse } from "../../utils/when";

export default defineRegexCheck({
  id: "azure-key-disclosure",
  name: "Azure Key Disclosed",
  description:
    "Detects Azure storage account keys and connection strings in HTTP responses",
  tags: [Tags.SECRET, Tags.CLOUD],
  severity: Severity.CRITICAL,
  patterns: [
    /(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{44,88}/,
    /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{44,88}/,
  ],
  dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  when: whenTextResponse,
  toFinding: (matches) => ({
    name: "Azure Key Disclosed",
    description: `Azure storage credentials detected in the response:\n${matches.map((m) => "- `" + m + "`").join("\n")}`,
  }),
});
