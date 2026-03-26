import { continueWith, defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { getBasePath, keyStrategy } from "../../utils/key";

const isValidNpmDebugLog = (bodyText: string): boolean => {
  if (bodyText.includes("npm ERR!")) {
    return true;
  }

  if (bodyText.includes("verbose") && bodyText.includes("npm")) {
    return true;
  }

  return false;
};

export default defineCheck<{
  basePath: string;
}>(({ step }) => {
  step("setupScan", (_, context) => {
    const basePath = getBasePath(context.target.request.getPath());

    return continueWith({
      nextStep: "testNpmDebugLog",
      state: { basePath },
    });
  });

  step("testNpmDebugLog", async (state, context) => {
    const logPath = state.basePath + "/npm-debug.log";
    const request = context.target.request.toSpec();

    request.setPath(logPath);
    request.setMethod("GET");
    request.setQuery("");
    request.setBody("");

    const result = await context.sdk.requests.send(request);

    if (result.response.getCode() === 200) {
      const body = result.response.getBody();
      if (body !== undefined) {
        const bodyText = body.toText();

        if (isValidNpmDebugLog(bodyText)) {
          return done({
            findings: [
              {
                name: "NPM Debug Log Exposed",
                description: `An \`npm-debug.log\` file is publicly accessible at \`${logPath}\`. This file may contain sensitive information such as internal paths, environment variables, and error details.`,
                severity: Severity.HIGH,
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

    return done({
      state,
    });
  });

  return {
    metadata: {
      id: "npm-debug-log",
      name: "NPM Debug Log Exposed",
      description:
        "Detects publicly accessible npm-debug.log files that may contain sensitive debugging information",
      type: "active",
      tags: [Tags.INFRASTRUCTURE, Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.HIGH],
      aggressivity: {
        minRequests: 1,
        maxRequests: 1,
      },
    },

    initState: () => ({ basePath: "" }),
    dedupeKey: keyStrategy().withHost().withPort().withBasePath().build(),
  };
});
