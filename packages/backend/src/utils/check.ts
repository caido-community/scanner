import {
  type CheckMetadata,
  defineCheck,
  done,
  type Finding,
  type RuntimeContext,
} from "engine";

import { extractBodyMatches } from "./body";
import { keyStrategy } from "./key";

export const defineResponseRegexCheck = (options: {
  patterns: RegExp[];
  toFindings: (matches: string[], runtimeContext: RuntimeContext) => Finding[];
  metadata: CheckMetadata;
}) => {
  return defineCheck(({ step }) => {
    step("scanResponse", (state, context) => {
      const response = context.target.response;
      if (response === undefined || response.getCode() !== 200) {
        return done({ state });
      }

      const matches = extractBodyMatches(response, options.patterns);
      if (matches.length > 0) {
        return done({
          findings: options.toFindings(matches, context),
          state,
        });
      }

      return done({ state });
    });

    return {
      metadata: options.metadata,
      initState: () => ({}),
      dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    };
  });
};
