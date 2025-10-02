import { Severity } from "engine";

import { defineResponseRegexCheck } from "../../utils/check";

// Private key regex patterns
const PRIVATE_KEY_PATTERNS = [
  // RSA Private Key
  /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/g,
  /-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/g,

  // DSA Private Key
  /-----BEGIN DSA PRIVATE KEY-----[\s\S]*?-----END DSA PRIVATE KEY-----/g,

  // EC Private Key
  /-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----/g,

  // OpenSSH Private Key
  /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g,

  // SSH2 Private Key
  /-----BEGIN SSH2 PRIVATE KEY-----[\s\S]*?-----END SSH2 PRIVATE KEY-----/g,

  // PGP Private Key
  /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g,

  // Generic private key patterns (base64 encoded)
  /-----BEGIN.*PRIVATE.*KEY-----[\s\S]*?-----END.*PRIVATE.*KEY-----/g,

  // SSH private key without headers (common in config files)
  /ssh-rsa AAAA[0-9A-Za-z+/]+=*[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g,
];

export default defineResponseRegexCheck({
  patterns: PRIVATE_KEY_PATTERNS,
  toFindings: (matches, context) => {
    const matchedKeys = matches.map((key) => `- ${key}`).join("\n");
    return [
      {
        name: "Private Key Disclosed",
        description: `Private keys have been detected in the response.\n\nDiscovered private keys:\n\`\`\`\n${matchedKeys}\n\`\`\``,
        severity: Severity.INFO,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      },
    ];
  },
  metadata: {
    id: "private-key-disclosure",
    name: "Private Key Disclosed",
    description:
      "Detects private keys in HTTP responses that could lead to complete system compromise",
    type: "passive",
    tags: ["information-disclosure", "sensitive-data"],
    severities: [Severity.INFO],
    aggressivity: {
      minRequests: 0,
      maxRequests: 0,
    },
  },
});
