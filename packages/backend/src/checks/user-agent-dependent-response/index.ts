import { defineCheckV2, Result, Severity } from "engine";

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

type ProbeResult = {
  userAgent: string;
  responseCode: number;
  bodyLength: number;
};

const bodyLength = (text: string | undefined): number =>
  text === undefined ? 0 : text.length;

const hasMeaningfulDifference = (
  left: { responseCode: number; bodyLength: number },
  right: { responseCode: number; bodyLength: number },
): boolean => {
  if (left.responseCode !== right.responseCode) {
    return true;
  }

  const lengthDifference = Math.abs(left.bodyLength - right.bodyLength);
  return lengthDifference > 100;
};

const hasProbeVariance = (probes: ProbeResult[]): boolean => {
  for (let i = 0; i < probes.length; i++) {
    const firstProbe = probes[i];
    if (firstProbe === undefined) {
      continue;
    }

    for (let j = i + 1; j < probes.length; j++) {
      const secondProbe = probes[j];
      if (secondProbe === undefined) {
        continue;
      }

      if (hasMeaningfulDifference(firstProbe, secondProbe)) {
        return true;
      }
    }
  }

  return false;
};

export default defineCheckV2({
  id: "user-agent-dependent-response",
  name: "User agent dependent response",
  description: "Detects differences in responses when varying the User-Agent header.",
  type: "active",
  tags: [Tags.INFORMATION_DISCLOSURE, Tags.INPUT_VALIDATION],
  severities: [Severity.INFO],
  aggressivity: {
    minRequests: USER_AGENTS.length,
    maxRequests: USER_AGENTS.length,
  },
  dedupeKey: keyStrategy().withHost().withPath().build(),
  when: (target) =>
    target.request.getMethod().toUpperCase() === "GET" &&
    target.response !== undefined,
  async execute(ctx) {
    const originalResponse = ctx.target.response;
    if (originalResponse === undefined) {
      return;
    }

    const probes: ProbeResult[] = [];

    for (const profile of USER_AGENTS) {
      const spec = ctx.target.request.toSpec();
      spec.setHeader("User-Agent", profile.value);

      const result = await ctx.send(spec);
      if (Result.isErr(result)) {
        continue;
      }

      probes.push({
        userAgent: profile.label,
        responseCode: result.value.response.getCode(),
        bodyLength: bodyLength(result.value.response.getBody()?.toText()),
      });
    }

    if (probes.length < 2) {
      return;
    }

    const original = {
      responseCode: originalResponse.getCode(),
      bodyLength: bodyLength(originalResponse.getBody()?.toText()),
    };

    const differences = probes.filter((probe) =>
      hasMeaningfulDifference(probe, original),
    );
    if (differences.length === 0) {
      return;
    }

    if (!hasProbeVariance(probes)) {
      return;
    }

    const details = differences
      .map((probe) => {
        return `- User agent \`${probe.userAgent}\` received status ${probe.responseCode} (body length ${probe.bodyLength}), while original response was status ${original.responseCode} (body length ${original.bodyLength})`;
      })
      .join("\n");

    const description = [
      "The response appears to vary based on the supplied `User-Agent` header.",
      "",
      details,
      "",
      "Such behaviour can indicate user-agent based content filtering or potential fingerprinting opportunities.",
    ].join("\n");

    ctx.finding({
      name: "User agent dependent response detected",
      description,
      severity: Severity.INFO,
    });
  },
});
