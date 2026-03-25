import {
  continueWith,
  defineCheck,
  done,
  ScanAggressivity,
  Severity,
} from "engine";

import { Tags } from "../../types";
import { findingBuilder } from "../../utils";
import { getBasePath, keyStrategy } from "../../utils/key";

type ProfilerEndpoint = {
  path: string;
  name: string;
};

const PROFILER_ENDPOINTS: ProfilerEndpoint[] = [
  {
    path: "_profiler/latest",
    name: "Symfony Profiler (latest)",
  },
  {
    path: "_profiler/open",
    name: "Symfony Profiler (open)",
  },
];

const SYMFONY_SIGNATURES = ["Symfony", "sf-toolbar", "profiler"];

function getEndpointsForAggressivity(
  aggressivity: ScanAggressivity,
): ProfilerEndpoint[] {
  switch (aggressivity) {
    case ScanAggressivity.LOW:
      return PROFILER_ENDPOINTS.slice(0, 1);
    case ScanAggressivity.MEDIUM:
    case ScanAggressivity.HIGH:
      return PROFILER_ENDPOINTS;
    default:
      return PROFILER_ENDPOINTS.slice(0, 1);
  }
}

function isValidProfilerResponse(body: string): boolean {
  return SYMFONY_SIGNATURES.some((sig) => body.includes(sig));
}

type State = {
  endpoints: ProfilerEndpoint[];
  basePath: string;
};

export default defineCheck<State>(({ step }) => {
  step("setupScan", (_, context) => {
    const basePath = getBasePath(context.target.request.getPath());
    const endpoints = getEndpointsForAggressivity(context.config.aggressivity);

    return continueWith({
      nextStep: "testEndpoint",
      state: {
        endpoints,
        basePath,
      },
    });
  });

  step("testEndpoint", async (state, context) => {
    if (state.endpoints.length === 0) {
      return done({ state });
    }

    const [currentEndpoint, ...remainingEndpoints] = state.endpoints;
    if (currentEndpoint === undefined) {
      return done({ state });
    }

    const fullPath = `${state.basePath}/${currentEndpoint.path}`;
    const request = context.target.request.toSpec();
    request.setPath(fullPath);
    request.setMethod("GET");
    request.setQuery("");
    request.setBody("");

    try {
      const result = await context.sdk.requests.send(request);

      if (result.response.getCode() === 200) {
        const body = result.response.getBody();
        if (body !== undefined) {
          const bodyText = body.toText();

          if (isValidProfilerResponse(bodyText)) {
            const finding = findingBuilder({
              name: "Symfony Profiler Exposed",
              severity: Severity.HIGH,
              request: result.request,
            })
              .withDescription(
                `The Symfony web profiler is publicly accessible at \`${fullPath}\`. This debug tool exposes detailed information about application requests, database queries, performance metrics, and internal configuration.`,
              )
              .withImpact(
                "Attackers can access detailed request profiling data including database queries with parameters, session information, security token details, and application configuration. This information can be used to craft further attacks.",
              )
              .withRecommendation(
                "Disable the Symfony web profiler in production by setting `APP_ENV=prod` and ensuring the `WebProfilerBundle` is only loaded in the `dev` environment. Restrict access to `_profiler` routes via firewall rules.",
              )
              .build();

            return done({
              state: { ...state, endpoints: remainingEndpoints },
              findings: [finding],
            });
          }
        }
      }
    } catch {
      /* empty */
    }

    return continueWith({
      nextStep: "testEndpoint",
      state: { ...state, endpoints: remainingEndpoints },
    });
  });

  return {
    metadata: {
      id: "symfony-profiler",
      name: "Symfony Profiler Exposed",
      description:
        "Detects exposed Symfony web profiler that can leak sensitive application debugging information",
      type: "active",
      tags: [Tags.FRAMEWORK, Tags.DEBUG],
      severities: [Severity.HIGH],
      aggressivity: {
        minRequests: 1,
        maxRequests: PROFILER_ENDPOINTS.length,
      },
    },

    initState: () => ({
      endpoints: [],
      basePath: "",
    }),
    dedupeKey: keyStrategy().withHost().withPort().withBasePath().build(),
  };
});
