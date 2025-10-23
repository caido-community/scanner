import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils";

const TRACE_MARKER_HEADER = "X-Trace-Detection";
const TRACE_MARKER_VALUE = "caido-trace-check";

type State = {
  probeSent: boolean;
};

const hasEchoedMarker = (bodyText: string): boolean => {
  const normalized = bodyText.toLowerCase();
  return (
    normalized.includes(TRACE_MARKER_HEADER.toLowerCase()) &&
    normalized.includes(TRACE_MARKER_VALUE.toLowerCase())
  );
};

export default defineCheck<State>(({ step }) => {
  step("sendTraceProbe", async (_, context) => {
    const spec = context.target.request.toSpec();
    spec.setMethod("TRACE");
    spec.setHeader(TRACE_MARKER_HEADER, TRACE_MARKER_VALUE);
    spec.setBody("");

    const result = await context.sdk.requests.send(spec);
    const response = result.response;

    if (response === undefined) {
      return done({
        state: { probeSent: true },
      });
    }

    const code = response.getCode();
    const bodyText = response.getBody()?.toText() ?? "";

    if (code === 200 && hasEchoedMarker(bodyText)) {
      const findingDescription = [
        "The server responded to an HTTP `TRACE` request with a 200 status code and echoed back custom headers.",
        "",
        "This behaviour indicates that the TRACE method is enabled, which can expose user cookies and authentication headers via cross-site tracing (XST) attacks.",
        "",
        `The echoed payload included the header \`${TRACE_MARKER_HEADER}: ${TRACE_MARKER_VALUE}\`.`,
      ].join("\n");

      return done({
        state: { probeSent: true },
        findings: [
          {
            name: "HTTP TRACE method enabled",
            description: findingDescription,
            severity: Severity.MEDIUM,
            correlation: {
              requestID: result.request.getId(),
              locations: [],
            },
          },
        ],
      });
    }

    return done({
      state: { probeSent: true },
    });
  });

  return {
    metadata: {
      id: "http-trace-enabled",
      name: "HTTP TRACE Method Enabled",
      description:
        "Detects servers that accept HTTP TRACE requests and echo request headers, enabling cross-site tracing attacks.",
      type: "active",
      tags: [Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.MEDIUM],
      aggressivity: {
        minRequests: 1,
        maxRequests: 1,
      },
    },
    initState: () => ({ probeSent: false }),
    dedupeKey: keyStrategy().withHost().withPath().build(),
    when: () => true,
  };
});
