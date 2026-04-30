import {
  continueWith,
  defineCheck,
  done,
  ScanAggressivity,
  Severity,
} from "engine";

import { keyStrategy } from "../../utils/key";
import { Tags } from "../tags";

const createOriginTests = (host: string, scheme: string) => {
  const tests = [
    {
      name: "arbitrary-origin-reflection",
      origin: `${scheme}://example.com`,
      description:
        "Tests if server reflects any origin in Access-Control-Allow-Origin header",
    },
    {
      name: "subdomain-wildcard",
      origin: `${scheme}://${host}.example.com`,
      description: "Tests if subdomains are allowed (e.g. target.example.com)",
    },
    {
      name: "domain-prefix",
      origin: `${scheme}://evil${host}`,
      description:
        "Tests if domains with target as suffix are allowed (e.g. eviltarget.com)",
    },
    {
      name: "null-origin",
      origin: "null",
      description: "Tests if null origin is allowed",
    },
    {
      name: "underscore-bypass",
      origin: `${scheme}://${host}_.example.com`,
      description: "Tests for underscore bypass (e.g. target_.example.com)",
    },
  ];

  if (host.split(".").length > 2) {
    tests.push({
      name: "regex-bypass",
      origin: `${scheme}://${host.replace(".", "x")}`,
      description: "Tests for unescaped dot bypass in regex patterns",
    });
  }

  return tests;
};

const createFinding = (
  testType: string,
  origin: string,
  allowOriginHeader: string,
  allowCredentialsHeader: string | undefined,
) => {
  const hasCredentials = allowCredentialsHeader?.toLowerCase() === "true";

  switch (testType) {
    case "arbitrary-origin-reflection":
      return {
        name: "CORS Arbitrary Origin Reflection",
        description: `The server reflects any origin back in the Access-Control-Allow-Origin header. This means an attacker can make the victim's browser send requests with credentials to this endpoint from any malicious website.

**Tested Origin:** \`${origin}\`

**Server Response:** \`Access-Control-Allow-Origin: ${allowOriginHeader}\`

**Credentials Allowed:** ${hasCredentials ? "Yes" : "No"}`,
        severity: hasCredentials ? Severity.LOW : Severity.INFO,
      };

    case "subdomain-wildcard":
      return {
        name: "CORS Subdomain Wildcard",
        description: `The server allows requests from subdomains of the target domain. If an attacker can control or register a subdomain, they can access this endpoint.

**Tested Origin:** \`${origin}\`

**Server Response:** \`Access-Control-Allow-Origin: ${allowOriginHeader}\`

**Credentials Allowed:** ${hasCredentials ? "Yes" : "No"}`,
        severity: hasCredentials ? Severity.LOW : Severity.INFO,
      };

    case "null-origin":
      return {
        name: "CORS Null Origin Allowed",
        description: `The server allows the 'null' origin, which can be triggered by sandboxed iframes, data URLs, and file URLs. Attackers can exploit this to bypass CORS protections.

**Tested Origin:** \`${origin}\`

**Server Response:** \`Access-Control-Allow-Origin: ${allowOriginHeader}\`

**Credentials Allowed:** ${hasCredentials ? "Yes" : "No"}`,
        severity: hasCredentials ? Severity.LOW : Severity.INFO,
      };

    case "underscore-bypass":
      return {
        name: "CORS Underscore Bypass",
        description: `The server accepts origins with underscore characters that may not be properly validated. This could allow subdomain takeover attacks.

**Tested Origin:** \`${origin}\`

**Server Response:** \`Access-Control-Allow-Origin: ${allowOriginHeader}\`

**Credentials Allowed:** ${hasCredentials ? "Yes" : "No"}`,
        severity: hasCredentials ? Severity.LOW : Severity.INFO,
      };

    case "regex-bypass":
      return {
        name: "CORS Regex Bypass",
        description: `The server uses unescaped dots in regex patterns for origin validation. The dot character matches any character in regex, allowing bypass of origin restrictions.

**Tested Origin:** \`${origin}\`

**Server Response:** \`Access-Control-Allow-Origin: ${allowOriginHeader}\`

**Credentials Allowed:** ${hasCredentials ? "Yes" : "No"}`,
        severity: hasCredentials ? Severity.LOW : Severity.INFO,
      };

    default:
      return undefined;
  }
};

export default defineCheck<{
  originTests: Array<{ name: string; origin: string; description: string }>;
  requestHost: string;
  requestScheme: string;
}>(({ step }) => {
  step("passiveCheck", (state, context) => {
    const { request, response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const allowOriginHeader = response.getHeader(
      "access-control-allow-origin",
    )?.[0];
    const allowCredentialsHeader = response.getHeader(
      "access-control-allow-credentials",
    )?.[0];

    if (
      allowOriginHeader === "*" &&
      allowCredentialsHeader?.toLowerCase() === "true"
    ) {
      return done({
        findings: [
          {
            name: "CORS Wildcard with Credentials",
            description: `The server responds with 'Access-Control-Allow-Origin: *' AND 'Access-Control-Allow-Credentials: true'. This configuration is forbidden by browsers and indicates a serious misconfiguration.\n\n**Access-Control-Allow-Origin:** \`${allowOriginHeader}\`\n**Access-Control-Allow-Credentials:** \`${allowCredentialsHeader}\`\n\nNote: Browsers will reject this combination, but it shows the server is misconfigured.`,
            severity: Severity.LOW,
            correlation: {
              requestID: request.getId(),
              locations: [],
            },
          },
        ],
        state,
      });
    }

    if (allowOriginHeader !== undefined) {
      const url = new URL(request.getUrl());
      const originTests = createOriginTests(
        url.hostname,
        url.protocol.slice(0, -1),
      );

      let maxTests: number;
      if (context.config.aggressivity === ScanAggressivity.LOW) {
        maxTests = 3;
      } else if (context.config.aggressivity === ScanAggressivity.MEDIUM) {
        maxTests = 5;
      } else {
        maxTests = originTests.length;
      }

      return continueWith({
        nextStep: "testOrigin",
        state: {
          originTests: originTests.slice(0, maxTests),
          requestHost: url.hostname,
          requestScheme: url.protocol.slice(0, -1),
        },
      });
    }

    return done({ state });
  });

  step("testOrigin", async (state, context) => {
    if (state.originTests.length === 0) {
      return done({ state });
    }

    const [currentTest, ...remainingTests] = state.originTests;
    if (currentTest === undefined) {
      return done({ state });
    }

    try {
      const spec = context.target.request.toSpec();
      spec.setHeader("Origin", currentTest.origin);

      const { request, response } = await context.sdk.requests.send(spec);

      const allowOriginHeader = response?.getHeader(
        "access-control-allow-origin",
      )?.[0];
      const allowCredentialsHeader = response?.getHeader(
        "access-control-allow-credentials",
      )?.[0];

      if (allowOriginHeader !== undefined) {
        let isVulnerable = false;

        if (currentTest.name === "null-origin") {
          isVulnerable = allowOriginHeader === "null";
        } else {
          isVulnerable = allowOriginHeader === currentTest.origin;
        }

        if (isVulnerable) {
          const finding = createFinding(
            currentTest.name,
            currentTest.origin,
            allowOriginHeader,
            allowCredentialsHeader,
          );

          if (finding) {
            return done({
              findings: [
                {
                  ...finding,
                  correlation: {
                    requestID: request.getId(),
                    locations: [],
                  },
                },
              ],
              state: { ...state, originTests: remainingTests },
            });
          }
        }
      }
    } catch {
      // Continue with next test on error
    }

    return continueWith({
      nextStep: "testOrigin",
      state: {
        ...state,
        originTests: remainingTests,
      },
    });
  });

  return {
    metadata: {
      id: "cors-misconfig",
      name: "CORS Misconfiguration",
      description:
        "Detects CORS misconfigurations including origin reflection, wildcard bypasses, null origins, and validation bypasses",
      type: "active",
      tags: [Tags.CORS],
      severities: [Severity.INFO, Severity.LOW],
      aggressivity: {
        minRequests: 0,
        maxRequests: 6,
      },
    },

    initState: () => ({
      originTests: [],
      requestHost: "",
      requestScheme: "",
    }),

    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  };
});
