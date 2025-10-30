import { continueWith, defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils";

type ProbeResult = {
  label: string;
  referer: string;
  responseCode?: number;
  bodyLength?: number;
};

type State = {
  baselineStatus: number;
  baselineLength: number;
  probes: ProbeResult[];
};

const EXTERNAL_REFERER = "https://attacker.example/";

const buildRefererProfiles = (
  currentUrl: string,
): Array<{ label: string; value: string }> => {
  try {
    const url = new URL(currentUrl);
    const sameOrigin = `${url.origin}${url.pathname}`;

    return [
      { label: "same-origin", value: sameOrigin },
      { label: "external", value: EXTERNAL_REFERER },
    ];
  } catch {
    return [{ label: "external", value: EXTERNAL_REFERER }];
  }
};

const getBodyLength = (text: string | undefined): number => {
  return text === undefined ? 0 : text.length;
};

const hasMeaningfulDifference = (
  baselineStatus: number,
  baselineLength: number,
  probe: ProbeResult,
): boolean => {
  if (probe.responseCode === undefined) {
    return true;
  }

  if (probe.responseCode !== baselineStatus) {
    return true;
  }

  if (probe.bodyLength === undefined) {
    return true;
  }

  const lengthDelta = Math.abs(probe.bodyLength - baselineLength);
  return lengthDelta > 100;
};

const buildDescription = (
  baselineStatus: number,
  baselineLength: number,
  probes: ProbeResult[],
): string => {
  const details = probes
    .map((probe) => {
      const status = probe.responseCode ?? "no response";
      const length =
        probe.bodyLength === undefined
          ? "no body"
          : `${probe.bodyLength} bytes`;
      return `- Referer \`${probe.label}\` (\`${probe.referer}\`) produced status ${status} with ${length}. Baseline response returned status ${baselineStatus} with ${baselineLength} bytes.`;
    })
    .join("\n");

  return [
    "The response differs when the `Referer` header is varied.",
    "",
    details,
    "",
    "Applications that alter behaviour based on `Referer` risk leaking data, breaking cache assumptions, or enabling access control bypasses. Avoid relying on `Referer` for security decisions and ensure consistent responses across origins.",
  ].join("\n");
};

export default defineCheck<State>(({ step }) => {
  step("probeReferers", async (_, context) => {
    const { request, response } = context.target;

    if (response === undefined) {
      return done({
        state: {
          baselineStatus: 0,
          baselineLength: 0,
          probes: [],
        },
      });
    }

    const baselineStatus = response.getCode();
    const baselineLength = getBodyLength(response.getBody()?.toText());
    const probes: ProbeResult[] = [];

    const profiles = buildRefererProfiles(request.getUrl());

    for (const profile of profiles) {
      const spec = request.toSpec();
      spec.setHeader("Referer", profile.value);

      const result = await context.sdk.requests.send(spec);
      const probeResponse = result.response;

      if (probeResponse === undefined) {
        probes.push({
          label: profile.label,
          referer: profile.value,
        });
        continue;
      }

      probes.push({
        label: profile.label,
        referer: profile.value,
        responseCode: probeResponse.getCode(),
        bodyLength: getBodyLength(probeResponse.getBody()?.toText()),
      });
    }

    return continueWith({
      nextStep: "evaluateDifferences",
      state: {
        baselineStatus,
        baselineLength,
        probes,
      },
    });
  });

  step("evaluateDifferences", (state, context) => {
    const differences = state.probes.filter((probe) =>
      hasMeaningfulDifference(
        state.baselineStatus,
        state.baselineLength,
        probe,
      ),
    );

    if (differences.length === 0) {
      return done({ state });
    }

    return done({
      state,
      findings: [
        {
          name: "Referer dependent response detected",
          description: buildDescription(
            state.baselineStatus,
            state.baselineLength,
            differences,
          ),
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
      id: "referer-dependent-response",
      name: "Referer dependent response",
      description:
        "Detects differential responses when the Referer header is varied between same-origin and external values.",
      type: "active",
      tags: [Tags.INFORMATION_DISCLOSURE, Tags.INPUT_VALIDATION],
      severities: [Severity.MEDIUM],
      aggressivity: {
        minRequests: 0,
        maxRequests: 3,
      },
    },
    initState: () => ({
      baselineStatus: 0,
      baselineLength: 0,
      probes: [],
    }),
    dedupeKey: keyStrategy().withHost().withPath().build(),
    when: () => true,
  };
});
