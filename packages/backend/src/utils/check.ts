import {
  type CheckMetadata,
  type CheckSpec,
  defineCheck,
  done,
  type Finding,
  Severity,
} from "engine";

import { extractBodyMatches } from "./body";
import { keyStrategy } from "./key";

export const defineResponseRegexCheck = <T>(options: {
  patterns: RegExp[];
  mapMatch: (match: string) => Finding;
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
          findings: matches.map(options.mapMatch),
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
