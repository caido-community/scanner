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
import { keyStrategy } from "../../utils/key";

type EndpointConfig = {
  path: string;
  name: string;
  severity: SeverityType;
  description: string;
  impact: string;
  validator: (body: string, contentType: string) => boolean;
};

const ACTUATOR_ENDPOINTS: EndpointConfig[] = [
  {
    path: "actuator/heapdump",
    name: "Spring Actuator Heapdump",
    severity: Severity.CRITICAL,
    description:
      "The heapdump endpoint is publicly accessible and can expose sensitive data including credentials, API keys, tokens, and session information stored in JVM memory.",
    impact:
      "Attackers can download the heap dump and extract sensitive credentials, AWS keys, JWT tokens, session cookies, and other secrets from memory.",
    validator: isValidHeapdumpContent,
  },
  {
    path: "actuator/env",
    name: "Spring Actuator Environment",
    severity: Severity.CRITICAL,
    description:
      "The env endpoint is publicly accessible and exposes environment variables including potential credentials, API keys, and database connection strings.",
    impact:
      "Attackers can retrieve sensitive configuration including database credentials, API keys, and cloud provider secrets.",
    validator: isValidEnvContent,
  },
  {
    path: "actuator/gateway/routes",
    name: "Spring Actuator Gateway Routes",
    severity: Severity.CRITICAL,
    description:
      "The gateway routes endpoint is publicly accessible. This can enable SSRF attacks and in vulnerable Spring Cloud Gateway versions can lead to remote code execution (CVE-2022-22947).",
    impact:
      "Attackers can create malicious routes to access internal services, cloud metadata endpoints (IMDS), or exploit RCE vulnerabilities.",
    validator: isValidGatewayRoutesContent,
  },
  {
    path: "actuator/metrics",
    name: "Spring Actuator Metrics",
    severity: Severity.MEDIUM,
    description:
      "The metrics endpoint is publicly accessible and exposes application performance metrics including JVM stats, HTTP request counts, and resource utilization.",
    impact:
      "Attackers can enumerate internal services, monitor application behavior, and gather information for further attacks.",
    validator: (body: string, ct: string) =>
      isJsonContentType(ct) && body.includes('"names"'),
  },
  {
    path: "actuator/beans",
    name: "Spring Actuator Beans",
    severity: Severity.HIGH,
    description:
      "The beans endpoint is publicly accessible and lists all Spring beans, their types, scopes, and dependencies.",
    impact:
      "Exposes internal application structure, bean configurations, and dependency injection graph that can guide targeted attacks.",
    validator: (body: string, ct: string) =>
      isJsonContentType(ct) && body.includes('"contexts"'),
  },
  {
    path: "actuator/mappings",
    name: "Spring Actuator Mappings",
    severity: Severity.HIGH,
    description:
      "The mappings endpoint is publicly accessible and lists all URL path mappings and their handler methods.",
    impact:
      "Exposes all API endpoints including hidden or internal routes and their handler classes.",
    validator: (body: string, ct: string) =>
      isJsonContentType(ct) &&
      (body.includes('"dispatcherServlets"') ||
        body.includes('"dispatcherHandlers"')),
  },
  {
    path: "actuator/loggers",
    name: "Spring Actuator Loggers",
    severity: Severity.HIGH,
    description:
      "The loggers endpoint is publicly accessible and allows viewing and modifying application log levels at runtime.",
    impact:
      "Attackers can change log levels to expose sensitive debug information or suppress security logging.",
    validator: (body: string, ct: string) =>
      isJsonContentType(ct) && body.includes('"levels"'),
  },
  {
    path: "actuator/threaddump",
    name: "Spring Actuator Thread Dump",
    severity: Severity.HIGH,
    description:
      "The threaddump endpoint is publicly accessible and exposes JVM thread state information.",
    impact:
      "Reveals internal execution state, potentially including sensitive data in thread stacks and class paths.",
    validator: (body: string, ct: string) =>
      body.includes("java.lang.Thread") ||
      (isJsonContentType(ct) && body.includes('"threads"')),
  },
];

type BypassTechnique = {
  name: string;
  transform: (basePath: string, endpoint: string) => string;
};

const BYPASS_TECHNIQUES: BypassTechnique[] = [
  {
    name: "direct",
    transform: (basePath, endpoint) => `${basePath}/${endpoint}`,
  },
  {
    name: "double-slash",
    transform: (basePath, endpoint) => `${basePath}//${endpoint}`,
  },
  {
    name: "url-encoded-slash",
    transform: (basePath, endpoint) => `${basePath}/%2F${endpoint}`,
  },
  {
    name: "tomcat-path-param",
    transform: (basePath, endpoint) => `${basePath}/..;/${endpoint}`,
  },
];

type PathVariant = {
  path: string;
  endpoint: EndpointConfig;
  bypassName: string;
};

function generatePathVariants(
  basePath: string,
  aggressivity: ScanAggressivity,
): PathVariant[] {
  const variants: PathVariant[] = [];
  const bypasses = getBypassesForAggressivity(aggressivity);

  for (const endpoint of ACTUATOR_ENDPOINTS) {
    for (const bypass of bypasses) {
      variants.push({
        path: bypass.transform(basePath, endpoint.path),
        endpoint,
        bypassName: bypass.name,
      });
    }
  }

  return variants;
}

function getBypassesForAggressivity(
  aggressivity: ScanAggressivity,
): BypassTechnique[] {
  switch (aggressivity) {
    case ScanAggressivity.LOW:
      return BYPASS_TECHNIQUES.slice(0, 1);
    case ScanAggressivity.MEDIUM:
      return BYPASS_TECHNIQUES.slice(0, 2);
    case ScanAggressivity.HIGH:
      return BYPASS_TECHNIQUES;
    default:
      return BYPASS_TECHNIQUES.slice(0, 1);
  }
}

function getBasePath(originalPath: string): string {
  return originalPath.split("/").slice(0, -1).join("/");
}

function isValidHeapdumpContent(
  bodyText: string,
  contentType: string,
): boolean {
  if (bodyText.length < 1000) {
    return false;
  }

  const normalizedContentType = contentType.toLowerCase();
  if (
    !normalizedContentType.includes("octet-stream") &&
    !normalizedContentType.includes("x-heap")
  ) {
    return false;
  }

  const hasJavaProfile = bodyText.startsWith("JAVA PROFILE");
  const hasJavaLangClass =
    bodyText.includes("java.lang.Class") ||
    bodyText.includes("java.lang.String") ||
    bodyText.includes("java.lang.Object");

  return hasJavaProfile || hasJavaLangClass;
}

function isValidEnvContent(bodyText: string, contentType: string): boolean {
  if (!isJsonContentType(contentType)) {
    return false;
  }

  try {
    const parsed = JSON.parse(bodyText);

    const hasPropertySources =
      "propertySources" in parsed && Array.isArray(parsed.propertySources);
    const hasActiveProfiles =
      "activeProfiles" in parsed && Array.isArray(parsed.activeProfiles);

    return hasPropertySources || hasActiveProfiles;
  } catch {
    return false;
  }
}

function isValidGatewayRoutesContent(
  bodyText: string,
  contentType: string,
): boolean {
  if (!isJsonContentType(contentType)) {
    return false;
  }

  try {
    const parsed = JSON.parse(bodyText);

    if (!Array.isArray(parsed)) {
      return false;
    }

    return parsed.some(
      (route) =>
        typeof route === "object" &&
        route !== null &&
        ("route_id" in route || "predicate" in route || "uri" in route),
    );
  } catch {
    return false;
  }
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

            const bypassInfo =
              currentVariant.bypassName !== "direct"
                ? ` (via ${currentVariant.bypassName} bypass)`
                : "";

            const finding = findingBuilder({
              name: currentVariant.endpoint.name,
              severity: currentVariant.endpoint.severity,
              request: result.request,
            })
              .withDescription(
                `${currentVariant.endpoint.description} Endpoint found at \`${currentVariant.path}\`${bypassInfo}.`,
              )
              .withImpact(currentVariant.endpoint.impact)
              .withRecommendation(
                "Disable or restrict access to Spring Boot Actuator endpoints. Use Spring Security to require authentication. Configure `management.endpoints.web.exposure.exclude` to disable unnecessary endpoints.",
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
      // Ignore errors
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
      id: "spring-actuator",
      name: "Spring Boot Actuator Exposure",
      description:
        "Detects exposed Spring Boot Actuator endpoints that can leak sensitive information and credentials",
      type: "active",
      tags: [Tags.INFORMATION_DISCLOSURE, Tags.RCE],
      severities: [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
      aggressivity: {
        minRequests: ACTUATOR_ENDPOINTS.length,
        maxRequests: ACTUATOR_ENDPOINTS.length * BYPASS_TECHNIQUES.length,
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
