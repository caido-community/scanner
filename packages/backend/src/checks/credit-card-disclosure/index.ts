import { Severity } from "engine";

import { defineResponseRegexCheck } from "../../utils/check";

// Credit card regex patterns based on Valibot implementation
const CREDIT_CARD_PATTERNS = [
  /\b3[47]\d{13}\b/g, // American Express
  /\b3(?:0[0-5]|[68]\d)\d{11,13}\b/g, // Diners Club
  /\b6(?:011|5\d{2})\d{12,15}\b/g, // Discover
  /\b(?:2131|1800|35\d{3})\d{11}\b/g, // JCB
  /\b(?:5[1-5]\d{2}|(?:222\d|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720))\d{12}\b/g, // Mastercard
  /\b(?:6[27]\d{14,17}|81\d{14,17})\b/g, // UnionPay
  /\b4\d{12}(?:\d{3,6})?\b/g, // Visa
];

export default defineResponseRegexCheck({
  patterns: CREDIT_CARD_PATTERNS,
  toFindings: (matches, context) => {
    const matchedCards = matches.map((card) => `- ${card}`).join("\n");
    return [
      {
        name: "Credit Card Number Disclosed",
        description: `Credit card numbers have been detected in the response. This could be a false positive and should be always manually verified.\n\nDiscovered credit card numbers:\n\`\`\`\n${matchedCards}\n\`\`\``,
        severity: Severity.INFO,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      },
    ];
  },
  metadata: {
    id: "credit-card-disclosure",
    name: "Credit Card Number Disclosed",
    description: "Detects credit card numbers in HTTP responses",
    type: "passive",
    tags: ["information-disclosure", "sensitive-data"],
    severities: [Severity.INFO],
    aggressivity: {
      minRequests: 0,
      maxRequests: 0,
    },
  },
});
