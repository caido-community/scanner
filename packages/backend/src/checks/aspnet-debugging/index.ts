import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils";

const DEBUG_MARKERS = [
  '<compilation debug="true"',
  '<compilation debug = "true"',
  '<compilation debug= "true"',
];

const bodyIndicatesDebugging = (body: string): boolean => {
  const lower = body.toLowerCase();
  return DEBUG_MARKERS.some((marker) => lower.includes(marker));
};

export default defineCheck(({ step }) => {
  step("detectAspNetDebug", (state, context) => {
    const { response, request } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const body = response.getBody()?.toText() ?? "";
    if (body.length === 0) {
      return done({ state });
    }

    if (!bodyIndicatesDebugging(body)) {
      return done({ state });
    }

    const description = [
      'The response appears to expose ASP.NET debugging configuration (`<compilation debug="true">`).',
      "",
      "Running in debug mode disables important optimisations and can disclose stack traces or sensitive data.",
      '**Recommendation:** Set `debug="false"` in Web.config for production deployments.',
    ].join("\n");

    return done({
      state,
      findings: [
        {
          name: "ASP.NET debugging enabled",
          description,
          severity: Severity.MEDIUM,
          correlation: {
            requestID: request.getId(),
            locations: [],
          },
        },
      ],
    });
  });

  return {
    metadata: {
      id: "aspnet-debugging",
      name: "ASP.NET debugging enabled",
      description:
        'Detects ASP.NET pages that indicate `debug="true"` in the compilation configuration.',
      type: "passive",
      tags: [Tags.DEBUG, Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.MEDIUM],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: () => true,
  };
});
