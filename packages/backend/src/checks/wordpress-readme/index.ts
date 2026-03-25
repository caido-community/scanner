import { continueWith, defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

const isValidWordPressReadme = (bodyText: string): boolean => {
  return bodyText.toLowerCase().includes("wordpress");
};

export default defineCheck<{
  tested: boolean;
}>(({ step }) => {
  step("setupScan", () => {
    return continueWith({
      nextStep: "testReadme",
      state: { tested: false },
    });
  });

  step("testReadme", async (state, context) => {
    const readmePath = "/readme.html";
    const request = context.target.request.toSpec();

    request.setPath(readmePath);
    request.setMethod("GET");
    request.setQuery("");
    request.setBody("");

    const result = await context.sdk.requests.send(request);

    if (result.response.getCode() === 200) {
      const body = result.response.getBody();
      if (body !== undefined) {
        const bodyText = body.toText();

        if (isValidWordPressReadme(bodyText)) {
          return done({
            findings: [
              {
                name: "WordPress Readme Exposed",
                description: `A WordPress \`readme.html\` file is publicly accessible at \`${readmePath}\`. This file may reveal the WordPress version and other platform details useful for targeted attacks.`,
                severity: Severity.INFO,
                correlation: {
                  requestID: result.request.getId(),
                  locations: [],
                },
              },
            ],
            state: { tested: true },
          });
        }
      }
    }

    return done({
      state: { tested: true },
    });
  });

  return {
    metadata: {
      id: "wordpress-readme",
      name: "WordPress Readme Exposed",
      description:
        "Detects publicly accessible WordPress readme.html files that may reveal version information",
      type: "active",
      tags: [Tags.INFRASTRUCTURE, Tags.ATTACK_SURFACE],
      severities: [Severity.INFO],
      aggressivity: {
        minRequests: 1,
        maxRequests: 1,
      },
    },

    initState: () => ({ tested: false }),
    dedupeKey: keyStrategy().withHost().withPort().build(),
  };
});
