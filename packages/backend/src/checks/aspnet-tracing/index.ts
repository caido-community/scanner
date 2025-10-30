import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils";

const TRACE_PATH = /trace\.axd$/i;
const TRACE_MARKERS = ["Trace Information", "Request Details", "Trace.axd"].map(
  (marker) => marker.toLowerCase(),
);

const responseLooksLikeTrace = (body: string): boolean => {
  const lower = body.toLowerCase();
  return TRACE_MARKERS.some((marker) => lower.includes(marker));
};

export default defineCheck(({ step }) => {
  step("detectTrace", (state, context) => {
    const { request, response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const path = request.getPath();
    if (!TRACE_PATH.test(path)) {
      return done({ state });
    }

    if (response.getCode() !== 200) {
      return done({ state });
    }

    const body = response.getBody()?.toText() ?? "";
    if (!responseLooksLikeTrace(body)) {
      return done({ state });
    }

    const description = [
      "The application exposes ASP.NET tracing output (`trace.axd`).",
      "",
      "Trace output can leak sensitive data (session IDs, connection strings) and should be disabled in production.",
      "**Recommendation:** Disable tracing in Web.config or restrict access to trace.axd.",
    ].join("\n");

    return done({
      state,
      findings: [
        {
          name: "ASP.NET tracing enabled",
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
      id: "aspnet-tracing",
      name: "ASP.NET tracing enabled",
      description: "Detects exposed ASP.NET trace.axd output.",
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
