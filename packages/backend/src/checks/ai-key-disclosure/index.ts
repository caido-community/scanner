import { defineRegexCheck, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";
import { whenTextResponse } from "../../utils/when";

export default defineRegexCheck({
  id: "ai-key-disclosure",
  name: "AI API Key Disclosed",
  description:
    "Detects API keys for AI services including OpenAI, Anthropic, HuggingFace, and Groq in HTTP responses",
  tags: [Tags.SECRET],
  severity: Severity.HIGH,
  patterns: [
    /\bsk-proj-[A-Za-z0-9_-]{40,}\b/,
    /\bsk-ant-api[0-9]{2}-[A-Za-z0-9_-]{95}\b/,
    /\bhf_[A-Za-z0-9]{34}\b/,
    /\bgsk_[A-Za-z0-9]{52}\b/,
  ],
  dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  when: whenTextResponse,
  toFinding: (matches) => ({
    name: "AI API Key Disclosed",
    description: `AI service API keys detected in the response:\n${matches.map((m) => "- `" + m + "`").join("\n")}`,
  }),
});
