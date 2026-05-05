import { RequestSpec } from "caido:utils";
import { continueWith, defineCheck, done, Severity } from "engine";

import { bodyMatchesAny } from "../../utils/body";
import { keyStrategy } from "../../utils/key";
import { Tags } from "../tags";

const ROBOTS_TXT_PATHS = [
  "/robots.txt",
  "/robots.TXT",
  "/ROBOTS.TXT",
  "/Robots.txt",
];

const ROBOTS_TXT_PATTERNS = [
  /User-Agent:\s*\*/i,
  /Disallow:\s*/i,
  /Allow:\s*/i,
  /Sitemap:\s*/i,
  /Crawl-Delay:\s*/i,
];

export default defineCheck<{
  remainingPaths: string[];
}>(({ step }) => {
  step("setupScan", (_, context) => {
    return continueWith({
      nextStep: "testRobotsPath",
      state: { remainingPaths: ROBOTS_TXT_PATHS },
    });
  });

  step("testRobotsPath", async (state, context) => {
    if (state.remainingPaths.length === 0) {
      return done({
        state,
      });
    }

    const [currentPath, ...remainingPaths] = state.remainingPaths;
    if (currentPath === undefined) {
      return done({
        state,
      });
    }

    const requestSpec = new RequestSpec(context.target.request.getUrl());
    requestSpec.setPath(currentPath);
    requestSpec.setQuery("");

    const result = await context.sdk.requests.send(requestSpec);

    if (result.response.getCode() === 200) {
      // Check if it's a valid robots.txt file
      if (bodyMatchesAny(result.response, ROBOTS_TXT_PATTERNS)) {
        return done({
          findings: [
            {
              name: "Robots.txt File Exposed",
              description: `Robots.txt file is publicly accessible at \`${currentPath}\`. This file may reveal directory structure, hidden paths, and crawling policies that could be useful for reconnaissance.`,
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

    return continueWith({
      nextStep: "testRobotsPath",
      state: {
        remainingPaths,
      },
    });
  });

  return {
    metadata: {
      id: "robots-txt",
      name: "Robots.txt File",
      description:
        "Detects publicly accessible robots.txt files that may reveal directory structure and crawling policies",
      type: "active",
      tags: [Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.INFO],
      aggressivity: {
        minRequests: 1,
        maxRequests: ROBOTS_TXT_PATHS.length,
      },
    },

    initState: () => ({ remainingPaths: [], basePath: "" }),
    dedupeKey: keyStrategy().withHost().withPort().build(),
  };
});
