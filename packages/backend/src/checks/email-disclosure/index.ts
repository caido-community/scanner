import { Severity } from "engine";

import { defineResponseRegexCheck } from "../../utils/check";

// Email address regex pattern
const EMAIL_PATTERNS = [/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g];

export default defineResponseRegexCheck({
  patterns: EMAIL_PATTERNS,
  toFindings: (matches, context) => {
    const matchedEmails = matches.map((email) => `- ${email}`).join("\n");
    return [
      {
        name: "Email Address Disclosed",
        description: `Email addresses have been detected in the response. \n\nDiscovered email addresses:\n\`\`\`\n${matchedEmails}\n\`\`\``,
        severity: Severity.INFO,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      },
    ];
  },
  metadata: {
    id: "email-disclosure",
    name: "Email Address Disclosed",
    description:
      "Detects email addresses in HTTP responses that could be used for phishing or spam",
    type: "passive",
    tags: ["information-disclosure", "sensitive-data"],
    severities: [Severity.INFO],
    aggressivity: {
      minRequests: 0,
      maxRequests: 0,
    },
  },
});
