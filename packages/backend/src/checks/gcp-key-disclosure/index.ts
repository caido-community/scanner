import { defineRegexCheck, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";
import { whenTextResponse } from "../../utils/when";

export default defineRegexCheck({
  id: "gcp-key-disclosure",
  name: "GCP Key Disclosed",
  description:
    "Detects Google Cloud Platform API keys and service account credentials in HTTP responses",
  tags: [Tags.SECRET, Tags.CLOUD],
  severity: Severity.HIGH,
  patterns: [/\bAIza[0-9A-Za-z_-]{35}\b/, /"type"\s*:\s*"service_account"/],
  dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  when: whenTextResponse,
  toFinding: (matches) => ({
    name: "GCP Key Disclosed",
    description: `Google Cloud Platform credentials detected in the response:\n${matches.map((m) => "- `" + m + "`").join("\n")}`,
  }),
});
