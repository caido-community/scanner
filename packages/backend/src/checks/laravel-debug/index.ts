import {
  continueWith,
  defineCheck,
  done,
  ScanAggressivity,
  Severity,
  type Severity as SeverityType,
} from "engine";

import { Tags } from "../../types";
import { findingBuilder, isJsonContentType } from "../../utils";
import { getBasePath, keyStrategy } from "../../utils/key";

type EndpointConfig = {
  path: string;
  name: string;
  severity: SeverityType;
  description: string;
  impact: string;
  validator: (body: string, contentType: string) => boolean;
};

function parseJsonObject(
  body: string,
  contentType: string,
): Record<string, unknown> | undefined {
  if (!isJsonContentType(contentType)) {
    return undefined;
  }

  try {
    const parsed: unknown = JSON.parse(body);

    if (typeof parsed !== "object" || parsed === null) {
      return undefined;
    }

    return parsed as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

function hasAnyKey(
  value: Record<string, unknown>,
  keys: readonly string[],
): boolean {
  return keys.some((key) => key in value);
}

const LARAVEL_ENDPOINTS: EndpointConfig[] = [
  {
    path: "_ignition/health-check",
    name: "Laravel Ignition Health Check",
    severity: Severity.HIGH,
    description:
      "The Laravel Ignition health check endpoint is publicly accessible. This debug tool can expose application internals and in vulnerable versions may allow remote code execution (CVE-2021-3129).",
    impact:
      "Attackers can confirm the application uses Laravel with Ignition debug mode enabled, and in vulnerable versions execute arbitrary code on the server.",
    validator: (body: string, contentType: string) => {
      const parsed = parseJsonObject(body, contentType);
      return (
        parsed !== undefined && hasAnyKey(parsed, ["can_execute_commands"])
      );
    },
  },
  {
    path: "__clockwork/api/latest",
    name: "Laravel Clockwork Debug Panel",
    severity: Severity.HIGH,
    description:
      "The Clockwork debug panel API is publicly accessible. This tool exposes detailed request profiling data including database queries, session data, and application internals.",
    impact:
      "Attackers can access detailed profiling information including SQL queries with parameters, session data, authentication details, and application configuration.",
    validator: (body: string, contentType: string) => {
      const parsed = parseJsonObject(body, contentType);
      return (
        parsed !== undefined &&
        hasAnyKey(parsed, ["id", "method", "uri", "time"])
      );
    },
  },
  {
    path: "telescope/api/requests",
    name: "Laravel Telescope Debug Dashboard",
    severity: Severity.HIGH,
    description:
      "The Laravel Telescope debug dashboard API is publicly accessible. This tool provides deep insight into requests, exceptions, logs, database queries, and more.",
    impact:
      "Attackers can view all application requests, exceptions with stack traces, database queries, log entries, and scheduled tasks.",
    validator: (body: string, contentType: string) => {
      const parsed = parseJsonObject(body, contentType);
      return (
        parsed !== undefined && hasAnyKey(parsed, ["data", "entries", "type"])
      );
    },
  },
];

type PathVariant = {
  path: string;
  endpoint: EndpointConfig;
};

function getEndpointsForAggressivity(
  aggressivity: ScanAggressivity,
): EndpointConfig[] {
  switch (aggressivity) {
    case ScanAggressivity.LOW:
      return LARAVEL_ENDPOINTS.slice(0, 1);
    case ScanAggressivity.MEDIUM:
      return LARAVEL_ENDPOINTS.slice(0, 2);
    case ScanAggressivity.HIGH:
      return LARAVEL_ENDPOINTS;
    default:
      return LARAVEL_ENDPOINTS.slice(0, 1);
  }
}

function generatePathVariants(
  basePath: string,
  aggressivity: ScanAggressivity,
): PathVariant[] {
  const endpoints = getEndpointsForAggressivity(aggressivity);
  return endpoints.map((endpoint) => ({
    path: `${basePath}/${endpoint.path}`,
    endpoint,
  }));
}

type State = {
  pathVariants: PathVariant[];
  basePath: string;
  detectedEndpoints: Set<string>;
};

export default defineCheck<State>(({ step }) => {
  step("setupScan", (_, context) => {
    const basePath = getBasePath(context.target.request.getPath());
    const pathVariants = generatePathVariants(
      basePath,
      context.config.aggressivity,
    );

    return continueWith({
      nextStep: "testEndpoint",
      state: {
        pathVariants,
        basePath,
        detectedEndpoints: new Set<string>(),
      },
    });
  });

  step("testEndpoint", async (state, context) => {
    if (state.pathVariants.length === 0) {
      return done({ state });
    }

    const [currentVariant, ...remainingVariants] = state.pathVariants;
    if (currentVariant === undefined) {
      return done({ state });
    }

    if (state.detectedEndpoints.has(currentVariant.endpoint.path)) {
      return continueWith({
        nextStep: "testEndpoint",
        state: {
          ...state,
          pathVariants: remainingVariants,
        },
      });
    }

    const request = context.target.request.toSpec();
    request.setPath(currentVariant.path);
    request.setMethod("GET");
    request.setQuery("");
    request.setBody("");

    try {
      const result = await context.sdk.requests.send(request);

      if (result.response.getCode() === 200) {
        const body = result.response.getBody();
        if (body !== undefined) {
          const bodyText = body.toText();
          const contentType =
            result.response.getHeader("content-type")?.[0] ?? "";

          if (currentVariant.endpoint.validator(bodyText, contentType)) {
            const newDetectedEndpoints = new Set(state.detectedEndpoints);
            newDetectedEndpoints.add(currentVariant.endpoint.path);

            const finding = findingBuilder({
              name: currentVariant.endpoint.name,
              severity: currentVariant.endpoint.severity,
              request: result.request,
            })
              .withDescription(
                `${currentVariant.endpoint.description} Endpoint found at \`${currentVariant.path}\`.`,
              )
              .withImpact(currentVariant.endpoint.impact)
              .withRecommendation(
                "Disable debug mode in production by setting `APP_DEBUG=false` in your `.env` file. Remove or restrict access to debug packages like Ignition, Clockwork, and Telescope in production deployments.",
              )
              .build();

            return continueWith({
              nextStep: "testEndpoint",
              state: {
                ...state,
                pathVariants: remainingVariants,
                detectedEndpoints: newDetectedEndpoints,
              },
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
      state: {
        ...state,
        pathVariants: remainingVariants,
      },
    });
  });

  return {
    metadata: {
      id: "laravel-debug",
      name: "Laravel Debug Tools Exposure",
      description:
        "Detects exposed Laravel debug tools including Ignition, Clockwork, and Telescope that can leak sensitive application data",
      type: "active",
      tags: [Tags.FRAMEWORK, Tags.DEBUG],
      severities: [Severity.HIGH],
      aggressivity: {
        minRequests: 1,
        maxRequests: LARAVEL_ENDPOINTS.length,
      },
    },

    initState: () => ({
      pathVariants: [],
      basePath: "",
      detectedEndpoints: new Set<string>(),
    }),
    dedupeKey: keyStrategy().withHost().withPort().withBasePath().build(),
  };
});
