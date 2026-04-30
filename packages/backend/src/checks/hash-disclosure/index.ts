import { defineCheck, done, Severity } from "engine";

import { keyStrategy } from "../../utils/key";
import { Tags } from "../tags";

// Common hash patterns - matching ZAP Proxy coverage
const HASH_PATTERNS = [
  // LanMan / DES hashes
  {
    pattern: /\$LM\$[a-f0-9]{16}/gi,
    name: "LanMan / DES",
    severity: Severity.HIGH,
  },
  {
    pattern: /\$K4\$[a-f0-9]{16},/gi,
    name: "Kerberos AFS DES",
    severity: Severity.HIGH,
  },

  // OpenBSD Blowfish
  {
    pattern: /\$2a\$05\$[a-z0-9+\-_./=]{53}/gi,
    name: "OpenBSD Blowfish",
    severity: Severity.HIGH,
  },
  {
    pattern: /\$2y\$05\$[a-z0-9+\-_./=]{53}/gi,
    name: "OpenBSD Blowfish",
    severity: Severity.HIGH,
  },

  // MD5 Crypt
  {
    pattern: /\$1\$[./0-9A-Za-z]{0,8}\$[./0-9A-Za-z]{22}/g,
    name: "MD5 Crypt",
    severity: Severity.HIGH,
  },

  // SHA-256 Crypt
  {
    pattern: /\$5\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{43}/g,
    name: "SHA-256 Crypt",
    severity: Severity.HIGH,
  },
  {
    pattern: /\$5\$rounds=[0-9]+\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{43}/g,
    name: "SHA-256 Crypt",
    severity: Severity.HIGH,
  },

  // SHA-512 Crypt
  {
    pattern: /\$6\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{86}/g,
    name: "SHA-512 Crypt",
    severity: Severity.HIGH,
  },
  {
    pattern: /\$6\$rounds=[0-9]+\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{86}/g,
    name: "SHA-512 Crypt",
    severity: Severity.HIGH,
  },

  // BCrypt
  {
    pattern: /\$2\$[0-9]{2}\$[./0-9A-Za-z]{53}/g,
    name: "BCrypt",
    severity: Severity.HIGH,
  },
  {
    pattern: /\$2a\$[0-9]{2}\$[./0-9A-Za-z]{53}/g,
    name: "BCrypt",
    severity: Severity.HIGH,
  },

  // NTLM
  {
    pattern: /\$3\$\$[0-9a-f]{32}/gi,
    name: "NTLM",
    severity: Severity.HIGH,
  },
  {
    pattern: /\$NT\$[0-9a-f]{32}/gi,
    name: "NTLM",
    severity: Severity.HIGH,
  },

  // Salted SHA-1 (48 hex characters)
  {
    pattern: /\b[0-9A-F]{48}\b/g,
    name: "Salted SHA-1",
    severity: Severity.LOW,
  },

  // SHA hashes (various lengths)
  {
    pattern: /\b[0-9a-f]{128}\b/gi,
    name: "SHA-512",
    severity: Severity.LOW,
  },
  {
    pattern: /\b[0-9a-f]{96}\b/gi,
    name: "SHA-384",
    severity: Severity.LOW,
  },
  // { Temporary disabled
  //   pattern: /\b[0-9a-f]{64}\b/gi,
  //   name: "SHA-256",
  //   severity: Severity.LOW,
  // },
  {
    pattern: /\b[0-9a-f]{56}\b/gi,
    name: "SHA-224",
    severity: Severity.LOW,
  },
  // {
  //   pattern: /\b[0-9a-f]{40}\b/gi,
  //   name: "SHA-1",
  //   severity: Severity.LOW,
  // },

  // MD4/MD5 Temporary disabled
  // {
  //   pattern: /\b[0-9a-f]{32}\b/gi,
  //   name: "MD4 / MD5",
  //   severity: Severity.LOW,
  // },

  // Modern hash types (keeping existing ones)
  {
    pattern: /\$2[aby]\$\d{2}\$[a-zA-Z0-9./]{53}/g,
    name: "bcrypt",
    severity: Severity.HIGH,
  },

  // Argon2 (starts with $argon2)
  {
    pattern:
      /\$argon2[di]d?\$v=\d+\$m=\d+,t=\d+,p=\d+\$[a-zA-Z0-9+/]+\$[a-zA-Z0-9+/]+/g,
    name: "Argon2",
    severity: Severity.HIGH,
  },

  // PBKDF2 (starts with $pbkdf2)
  {
    pattern: /\$pbkdf2[^$]+\$[a-zA-Z0-9+/]+/g,
    name: "PBKDF2",
    severity: Severity.HIGH,
  },

  // scrypt (starts with $scrypt)
  {
    pattern: /\$scrypt\$[a-zA-Z0-9+/]+/g,
    name: "scrypt",
    severity: Severity.HIGH,
  },

  // Apache htpasswd (starts with $apr1$)
  {
    pattern: /\$apr1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}/g,
    name: "Apache htpasswd",
    severity: Severity.HIGH,
  },
];

// Common hash-like patterns that are likely false positives
const FALSE_POSITIVE_PATTERNS = [
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // UUIDs
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // GUIDs
  /^[0-9a-f]{8}$/i, // Short hex strings (likely not hashes)
  /^[0-9a-f]{16}$/i, // 16-char hex strings (likely not hashes)
  /^[0-9a-f]{24}$/i, // 24-char hex strings (likely not hashes)
];

export default defineCheck<Record<never, never>>(({ step }) => {
  step("checkHashDisclosure", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const body = response.getBody()?.toText();
    if (body === undefined) {
      return done({ state });
    }

    const findings = [];

    for (const hashType of HASH_PATTERNS) {
      const matches = body.match(hashType.pattern);
      if (matches) {
        for (const match of matches) {
          // Skip if it's likely a false positive
          if (FALSE_POSITIVE_PATTERNS.some((pattern) => pattern.test(match))) {
            continue;
          }

          // Skip JSESSIONID values
          if (match.length === 32 && body.includes(`jsessionid=${match}`)) {
            continue;
          }

          const finding = {
            name: `${hashType.name} Hash Disclosure`,
            description: `A ${hashType.name} hash was found in the response. This may indicate that password hashes or other sensitive cryptographic data is being exposed. If these are password hashes, they could be cracked offline to obtain the original passwords.\n\nDiscovered hash: \`\`\`\n${match}\n\`\`\``,
            severity: hashType.severity,
            correlation: {
              requestID: context.target.request.getId(),
              locations: [],
            },
          };

          findings.push(finding);
        }
      }
    }

    if (findings.length > 0) {
      return done({ state, findings });
    }

    return done({ state });
  });

  return {
    metadata: {
      id: "hash-disclosure",
      name: "Hash Disclosure",
      description:
        "Detects exposed cryptographic hashes that may indicate password hash disclosure or other sensitive data exposure",
      type: "passive",
      tags: [
        Tags.HASH,
        Tags.PASSWORD,
        Tags.INFORMATION_DISCLOSURE,
        Tags.CRYPTOGRAPHY,
      ],
      severities: [Severity.HIGH, Severity.MEDIUM, Severity.LOW],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: (context) => context.response !== undefined,
  };
});
