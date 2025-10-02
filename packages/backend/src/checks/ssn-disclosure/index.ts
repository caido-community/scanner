import { Severity } from "engine";

import { defineResponseRegexCheck } from "../../utils/check";

// Social Security Number regex patterns
const SSN_PATTERNS = [
  // Standard SSN format: XXX-XX-XXXX
  /\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b/,
  // SSN with spaces: XXX XX XXXX
  /\b[0-9]{3}\s[0-9]{2}\s[0-9]{4}\b/,
  // SSN with dots: XXX.XX.XXXX
  /\b[0-9]{3}\.[0-9]{2}\.[0-9]{4}\b/,
];

export default defineResponseRegexCheck({
  patterns: SSN_PATTERNS,
  toFindings: (matches, context) => [
    {
      name: "Social Security Number Disclosed",
      description:
        "Social Security Numbers have been detected in the response.",
      severity: Severity.INFO,
      correlation: {
        requestID: context.target.request.getId(),
        locations: [],
      },
    },
  ],
  metadata: {
    id: "ssn-disclosure",
    name: "Social Security Number Disclosed",
    description:
      "Detects Social Security Numbers in HTTP responses that could lead to identity theft",
    type: "passive",
    tags: ["information-disclosure", "sensitive-data"],
    severities: [Severity.INFO],
    aggressivity: {
      minRequests: 0,
      maxRequests: 0,
    },
  },
});
