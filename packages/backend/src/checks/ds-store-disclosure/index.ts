import { continueWith, defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { getBasePath, keyStrategy } from "../../utils/key";

const DS_STORE_MAGIC = "\x00\x00\x00\x01";
const BUD1_MAGIC = "Bud1";

export default defineCheck<{
  basePath: string;
}>(({ step }) => {
  step("setupScan", (_, context) => {
    const basePath = getBasePath(context.target.request.getPath());

    return continueWith({
      nextStep: "testDsStore",
      state: { basePath },
    });
  });

  step("testDsStore", async (state, context) => {
    const dsStorePath = state.basePath + "/.DS_Store";
    const request = context.target.request.toSpec();

    request.setPath(dsStorePath);
    request.setMethod("GET");
    request.setQuery("");
    request.setBody("");

    const result = await context.sdk.requests.send(request);

    if (result.response.getCode() === 200) {
      const body = result.response.getBody();
      if (body !== undefined) {
        const bodyText = body.toText();

        if (
          bodyText.length > 4 &&
          (bodyText.startsWith(DS_STORE_MAGIC) || bodyText.includes(BUD1_MAGIC))
        ) {
          return done({
            findings: [
              {
                name: "DS_Store File Disclosed",
                description: `A \`.DS_Store\` file is publicly accessible at \`${dsStorePath}\`. This macOS metadata file may reveal directory contents and filenames.`,
                severity: Severity.MEDIUM,
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
      id: "ds-store-disclosure",
      name: "DS_Store File Disclosed",
      description:
        "Detects publicly accessible .DS_Store files that may reveal directory contents",
      type: "active",
      tags: [Tags.INFRASTRUCTURE, Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.MEDIUM],
      aggressivity: {
        minRequests: 1,
        maxRequests: 1,
      },
    },

    initState: () => ({ basePath: "" }),
    dedupeKey: keyStrategy().withHost().withPort().withBasePath().build(),
  };
});
