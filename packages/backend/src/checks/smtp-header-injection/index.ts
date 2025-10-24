import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { extractParameters } from "../../utils";
import { keyStrategy } from "../../utils/key";

const HEADER_PREFIX =
  /^(to|from|cc|bcc|reply-to|subject|mime-version|content-(type|transfer-encoding)):/i;
const NEWLINE_SEQUENCE = /%0a|%0d|\r|\n/i;

const isSuspiciousValue = (raw: string): boolean => {
  if (raw.length === 0) {
    return false;
  }

  if (NEWLINE_SEQUENCE.test(raw)) {
    return true;
  }

  const decoded = decodeURIComponent(raw).toLowerCase();
  return HEADER_PREFIX.test(decoded);
};

const buildDescription = (
  params: Array<{ name: string; source: string }>,
): string => {
  const lines = params
    .map((param) => `- Parameter \`${param.name}\` from ${param.source}`)
    .join("\n");

  return [
    "User-controlled input contains SMTP header sequences (newline characters or header prefixes).",
    "",
    lines,
    "",
    "SMTP header injection can allow attackers to add extra recipients or modify email contents. Strip CRLF sequences and validate header fields before including user data in outbound e-mails.",
  ].join("\n");
};

export default defineCheck<Record<never, never>>(({ step }) => {
  step("detectSmtpInjection", (state, context) => {
    const parameters = extractParameters(context);

    const flagged = parameters.filter((param) =>
      isSuspiciousValue(param.value),
    );

    if (flagged.length === 0) {
      return done({ state });
    }

    const evidence = flagged.map((param) => ({
      name: param.name,
      source: param.source,
    }));

    return done({
      state,
      findings: [
        {
          name: "SMTP header injection indicators",
          description: buildDescription(evidence),
          severity: Severity.MEDIUM,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        },
      ],
    });
  });

  return {
    metadata: {
      id: "smtp-header-injection",
      name: "SMTP header injection",
      description:
        "Detects user inputs containing SMTP header sequences, indicating possible header injection attempts.",
      type: "passive",
      tags: [Tags.INJECTION],
      severities: [Severity.MEDIUM],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPath().withQuery().build(),
    when: () => true,
  };
});
