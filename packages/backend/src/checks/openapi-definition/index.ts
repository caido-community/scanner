import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils";

type FindingData = {
  format: "json" | "yaml";
  version?: string;
};

const YAML_PATTERN = /\b(openapi|swagger)\s*:\s*["']?([\d.]+)["']?/i;

const parseOpenApiJson = (body: string): FindingData | undefined => {
  try {
    const json = JSON.parse(body) as Record<string, unknown>;

    if (json === null || typeof json !== "object") {
      return undefined;
    }

    const version =
      typeof json.openapi === "string"
        ? json.openapi
        : typeof json.swagger === "string"
          ? json.swagger
          : undefined;

    if (version === undefined) {
      return undefined;
    }

    if (
      json.paths !== undefined &&
      typeof json.paths === "object" &&
      json.info !== undefined
    ) {
      return { format: "json", version };
    }
  } catch {
    // Not JSON, ignore
  }

  return undefined;
};

const parseOpenApiYaml = (body: string): FindingData | undefined => {
  const match = body.match(YAML_PATTERN);
  if (match === null) {
    return undefined;
  }

  const version = match[2];
  if (version === undefined) {
    return undefined;
  }

  if (/\bpaths\s*:\s*/i.test(body) && /\binfo\s*:\s*/i.test(body)) {
    return { format: "yaml", version };
  }

  return undefined;
};

const buildDescription = (data: FindingData): string => {
  const formatText = data.format === "json" ? "JSON" : "YAML";
  const versionText =
    data.version !== undefined ? ` (version ${data.version})` : "";

  return [
    `An OpenAPI definition${versionText} was returned in the response (${formatText}).`,
    "",
    "OpenAPI/Swagger documentation often exposes full API surface area and can assist attackers in discovering sensitive endpoints or understanding authentication flows.",
    "",
    "Restrict access to API documentation in production or ensure it does not contain sensitive endpoints.",
  ].join("\n");
};

export default defineCheck<Record<never, never>>(({ step }) => {
  step("detectOpenApiDefinition", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const body = response.getBody()?.toText();
    if (body === undefined || body.length === 0) {
      return done({ state });
    }

    const findingData = parseOpenApiJson(body) ?? parseOpenApiYaml(body);

    if (findingData === undefined) {
      return done({ state });
    }

    return done({
      state,
      findings: [
        {
          name: "OpenAPI definition exposed",
          description: buildDescription(findingData),
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
      id: "openapi-definition-found",
      name: "OpenAPI definition exposed",
      description:
        "Detects responses that expose OpenAPI/Swagger service definitions.",
      type: "passive",
      tags: [Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.MEDIUM],
      aggressivity: {
        minRequests: 0,
        maxRequests: 0,
      },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPath().build(),
    when: (target) => target.response !== undefined,
  };
});
