import { defineCheck, done, Severity } from "engine";

import { keyStrategy } from "../../utils/key";
import { Tags } from "../tags";

export default defineCheck(({ step }) => {
  step("checkJsonHtmlResponse", (state, context) => {
    const response = context.target.response;
    if (!response) {
      return done({
        state,
      });
    }

    const contentType = response.getHeader("content-type")?.[0];
    if (contentType === undefined || !contentType.includes("text/html")) {
      return done({
        state,
      });
    }

    const body = response.getBody();
    if (!body) {
      return done({
        state,
      });
    }

    const bodyText = body.toText();
    if (!bodyText.trim()) {
      return done({
        state,
      });
    }

    try {
      const result = JSON.parse(bodyText);

      if (typeof result === "object" && result !== null) {
        return done({
          findings: [
            {
              name: "JSON Response with HTML Content-Type",
              description: `Response contains valid JSON data but has 'text/html' Content-Type header. This may lead to XSS attacks.`,
              severity: Severity.INFO,
              correlation: {
                requestID: context.target.request.getId(),
                locations: [],
              },
            },
          ],
          state,
        });
      }
    } catch {
      return done({
        state,
      });
    }

    return done({
      state,
    });
  });

  return {
    metadata: {
      id: "json-html-response",
      name: "JSON Response with HTML Content-Type",
      description:
        "Detects responses that contain valid JSON but have text/html Content-Type header",
      type: "passive",
      tags: [Tags.XSS],
      severities: [Severity.INFO],
      aggressivity: {
        minRequests: 0,
        maxRequests: 0,
      },
    },

    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: (context) => {
      return (
        context.response !== undefined && context.response.getCode() === 200
      );
    },
  };
});
