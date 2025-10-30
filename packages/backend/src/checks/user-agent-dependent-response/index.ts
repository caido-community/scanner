import { continueWith, defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils";

const USER_AGENTS = [
  {
    label: "desktop",
    value:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
  },
  {
    label: "mobile",
    value:
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
  },
];

type State = {
  originalStatus: number;
  originalLength: number;
  probes: {
    userAgent: string;
    responseCode: number;
    bodyLength: number;
  }[];
};

const bodyLength = (text: string | undefined): number =>
  text === undefined ? 0 : text.length;

export default defineCheck<State>(({ step }) => {
  step("probeUserAgents", async (state, context) => {
    const { request, response } = context.target;
    if (response === undefined) {
      return done({ state });
    }

    const probes: State["probes"] = [];

    for (const profile of USER_AGENTS) {
      const spec = request.toSpec();
      spec.setHeader("User-Agent", profile.value);

      const result = await context.sdk.requests.send(spec);
      const probeResponse = result.response;
      if (probeResponse === undefined) {
        continue;
      }

      probes.push({
        userAgent: profile.label,
        responseCode: probeResponse.getCode(),
        bodyLength: bodyLength(probeResponse.getBody()?.toText()),
      });
    }

    return continueWith({
      nextStep: "evaluateDifferences",
      state: {
        originalStatus: response.getCode(),
        originalLength: bodyLength(response.getBody()?.toText()),
        probes,
      },
    });
  });

  step("evaluateDifferences", (state, context) => {
    if (state.probes.length === 0) {
      return done({ state });
    }

    const originalStatus = state.originalStatus;
    const originalLength = state.originalLength;

    const differences = state.probes.filter((probe) => {
      if (probe.responseCode !== originalStatus) {
        return true;
      }

      const lengthDifference = Math.abs(probe.bodyLength - originalLength);
      return lengthDifference > 100;
    });

    if (differences.length === 0) {
      return done({ state });
    }

    const details = differences
      .map((probe) => {
        return `- User agent \`${probe.userAgent}\` received status ${probe.responseCode} (body length ${probe.bodyLength}), while original response was status ${originalStatus} (body length ${originalLength})`;
      })
      .join("\n");

    const description = [
      "The response appears to vary based on the supplied `User-Agent` header.",
      "",
      details,
      "",
      "Such behaviour can indicate user-agent based content filtering or potential fingerprinting opportunities.",
    ].join("\n");

    return done({
      state,
      findings: [
        {
          name: "User agent dependent response detected",
          description,
          severity: Severity.MEDIUM,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        },
      ],
    });
  });

  return {
    metadata: {
      id: "user-agent-dependent-response",
      name: "User agent dependent response",
      description:
        "Detects differences in responses when varying the User-Agent header.",
      type: "active",
      tags: [Tags.INFORMATION_DISCLOSURE, Tags.INPUT_VALIDATION],
      severities: [Severity.MEDIUM],
      aggressivity: { minRequests: 0, maxRequests: 4 },
    },
    initState: () => ({ originalStatus: 0, originalLength: 0, probes: [] }),
    dedupeKey: keyStrategy().withHost().withPath().build(),
    when: () => true,
  };
});
