import { Severity } from "engine";

import { defineResponseRegexCheck } from "../../utils/check";

// Private IP address regex patterns
const PRIVATE_IP_PATTERNS = [
  // RFC 1918 Private IP ranges
  // 10.0.0.0/8 (10.0.0.0 to 10.255.255.255)
  /\b10\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,

  // 172.16.0.0/12 (172.16.0.0 to 172.31.255.255)
  /\b172\.(1[6-9]|2[0-9]|3[0-1])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,

  // 192.168.0.0/16 (192.168.0.0 to 192.168.255.255)
  /\b192\.168\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,

  // Link-local addresses (169.254.0.0/16)
  /\b169\.254\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,

  // Loopback addresses (127.0.0.0/8)
  /\b127\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
];

export default defineResponseRegexCheck({
  patterns: PRIVATE_IP_PATTERNS,
  toFindings: (matches, context) => [
    {
      name: "Private IP Address Disclosed",
      description: "Private IP addresses have been detected in the response.",
      severity: Severity.INFO,
      correlation: {
        requestID: context.target.request.getId(),
        locations: [],
      },
    },
  ],
  metadata: {
    id: "private-ip-disclosure",
    name: "Private IP Address Disclosed",
    description:
      "Detects private IP addresses in HTTP responses that could reveal internal network infrastructure",
    type: "passive",
    tags: ["information-disclosure", "sensitive-data"],
    severities: [Severity.INFO],
    aggressivity: {
      minRequests: 0,
      maxRequests: 0,
    },
  },
});
