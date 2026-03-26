import {
  continueWith,
  defineCheck,
  done,
  ScanAggressivity,
  Severity,
} from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

const SECURITY_TXT_PATHS = [".well-known/security.txt", "security.txt"];

const getSecurityTxtPathsToTest = (
  aggressivity: ScanAggressivity,
): string[] => {
  switch (aggressivity) {
    case ScanAggressivity.LOW:
      return SECURITY_TXT_PATHS.slice(0, 1);
    case ScanAggressivity.MEDIUM:
    case ScanAggressivity.HIGH:
      return SECURITY_TXT_PATHS;
    default:
      return SECURITY_TXT_PATHS.slice(0, 1);
  }
};

const isValidSecurityTxt = (bodyText: string): boolean => {
  return bodyText.includes("Contact:");
};

export default defineCheck<{
  paths: string[];
}>(({ step }) => {
  step("setupScan", (_, context) => {
    const paths = getSecurityTxtPathsToTest(context.config.aggressivity);

    return continueWith({
      nextStep: "testSecurityTxt",
      state: { paths },
    });
  });

  step("testSecurityTxt", async (state, context) => {
    if (state.paths.length === 0) {
      return done({
        state,
      });
    }

    const [currentPath, ...remainingPaths] = state.paths;
    if (currentPath === undefined) {
      return done({
        state,
      });
    }

    const securityTxtPath = "/" + currentPath;
    const request = context.target.request.toSpec();

    request.setPath(securityTxtPath);
    request.setMethod("GET");
    request.setQuery("");
    request.setBody("");

    const result = await context.sdk.requests.send(request);

    if (result.response.getCode() === 200) {
      const body = result.response.getBody();
      if (body !== undefined) {
        const bodyText = body.toText();

        if (isValidSecurityTxt(bodyText)) {
          return done({
            findings: [
              {
                name: "Security.txt File Found",
                description: `A \`security.txt\` file (RFC 9116) is publicly accessible at \`${securityTxtPath}\`. This file provides security contact information for the organization.`,
                severity: Severity.INFO,
                correlation: {
                  requestID: result.request.getId(),
                  locations: [],
                },
              },
            ],
            state,
          });
        }
      }
    }

    return continueWith({
      nextStep: "testSecurityTxt",
      state: {
        paths: remainingPaths,
      },
    });
  });

  return {
    metadata: {
      id: "security-txt",
      name: "Security.txt File Found",
      description:
        "Detects publicly accessible security.txt files (RFC 9116) that provide security contact information",
      type: "active",
      tags: [Tags.INFRASTRUCTURE],
      severities: [Severity.INFO],
      aggressivity: {
        minRequests: 1,
        maxRequests: SECURITY_TXT_PATHS.length,
      },
    },

    initState: () => ({ paths: [] }),
    dedupeKey: keyStrategy().withHost().withPort().build(),
  };
});
