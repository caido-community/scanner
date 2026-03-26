import {
  continueWith,
  defineCheck,
  done,
  ScanAggressivity,
  Severity,
} from "engine";

import { Tags } from "../../types";
import { containsCanary, generateCanary } from "../../utils/canary";
import { keyStrategy } from "../../utils/key";

type HostVariant = {
  name: string;
  apply: (
    spec: { setHeader: (name: string, value: string) => void },
    canaryHost: string,
  ) => void;
};

const HOST_VARIANTS: HostVariant[] = [
  {
    name: "Host header replacement",
    apply: (spec, canaryHost) => {
      spec.setHeader("Host", canaryHost);
    },
  },
  {
    name: "X-Forwarded-Host injection",
    apply: (spec, canaryHost) => {
      spec.setHeader("X-Forwarded-Host", canaryHost);
    },
  },
  {
    name: "X-Host injection",
    apply: (spec, canaryHost) => {
      spec.setHeader("X-Host", canaryHost);
    },
  },
  {
    name: "Forwarded host injection",
    apply: (spec, canaryHost) => {
      spec.setHeader("Forwarded", `host=${canaryHost}`);
    },
  },
];

function getVariantsForAggressivity(
  aggressivity: ScanAggressivity,
): HostVariant[] {
  switch (aggressivity) {
    case ScanAggressivity.LOW:
      return HOST_VARIANTS.slice(0, 2);
    case ScanAggressivity.MEDIUM:
      return HOST_VARIANTS.slice(0, 3);
    case ScanAggressivity.HIGH:
      return HOST_VARIANTS;
    default:
      return HOST_VARIANTS.slice(0, 2);
  }
}

type State = {
  hostnameReflected: boolean;
  hostname: string;
  variants: HostVariant[];
};

export default defineCheck<State>(({ step }) => {
  step("baseline", (state, context) => {
    const { response, request } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const body = response.getBody();
    if (body === undefined) {
      return done({ state });
    }

    const baselineBody = body.toText();
    const hostname = request.getHost();

    if (!baselineBody.includes(hostname)) {
      return done({ state });
    }

    const variants = getVariantsForAggressivity(context.config.aggressivity);

    return continueWith({
      nextStep: "testVariants",
      state: {
        hostnameReflected: baselineBody.includes(hostname),
        hostname,
        variants,
      },
    });
  });

  step("testVariants", async (state, context) => {
    if (state.variants.length === 0) {
      return done({ state });
    }

    const [currentVariant, ...remainingVariants] = state.variants;
    if (currentVariant === undefined) {
      return done({ state });
    }

    const canary = generateCanary();
    const canaryHost = `canary-${canary}.example.com`;

    const spec = context.target.request.toSpec();
    spec.setQuery("");
    spec.setBody("");
    currentVariant.apply(spec, canaryHost);

    try {
      const result = await context.sdk.requests.send(spec);
      const responseBody = result.response.getBody()?.toText();

      if (responseBody !== undefined && containsCanary(responseBody, canary)) {
        return done({
          state: { ...state, variants: remainingVariants },
          findings: [
            {
              name: `Host Value Reflected via ${currentVariant.name}`,
              description: `The injected host value \`${canaryHost}\` was reflected in the response body using the **${currentVariant.name}** technique. This may indicate the application is susceptible to host header attacks such as cache poisoning or password reset poisoning, but requires manual verification to confirm exploitability.`,
              severity: Severity.MEDIUM,
              correlation: {
                requestID: result.request.getId(),
                locations: [],
              },
            },
          ],
        });
      }
    } catch {
      /* empty */
    }

    return continueWith({
      nextStep: "testVariants",
      state: { ...state, variants: remainingVariants },
    });
  });

  return {
    metadata: {
      id: "host-header-injection",
      name: "Host Value Reflection",
      description:
        "Detects when injected host header values are reflected in response bodies, which may indicate susceptibility to host header attacks",
      type: "active",
      tags: [Tags.HOST_HEADER],
      severities: [Severity.MEDIUM],
      aggressivity: {
        minRequests: 2,
        maxRequests: 4,
      },
    },

    initState: () => ({
      hostnameReflected: false,
      hostname: "",
      variants: [],
    }),
    dedupeKey: keyStrategy().withHost().withPort().build(),
  };
});
