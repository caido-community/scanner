import { defineCheck, done, type ScanTarget, Severity } from "engine";

import { Tags } from "../../../types";
import { keyStrategy } from "../../../utils/key";

const GRAPHQL_PATH_PATTERNS = [
  /\/graphql\/?$/i,
  /\/graphql\/v\d+\/?$/i,
  /\/api\/graphql\/?$/i,
  /\/gql\/?$/i,
];

type GraphQLRequest = {
  operationName?: string;
  query?: string;
  variables?: unknown;
};

type GraphQLResponse = {
  data?: unknown;
  errors?: unknown[];
};

function isGraphQLRequest(body: string): boolean {
  try {
    const parsed = JSON.parse(body) as GraphQLRequest;

    if (typeof parsed !== "object" || parsed === null) {
      return false;
    }

    const hasQuery = "query" in parsed && typeof parsed.query === "string";
    const hasOperationName =
      "operationName" in parsed &&
      (typeof parsed.operationName === "string" ||
        parsed.operationName === null);

    return hasQuery || hasOperationName;
  } catch {
    return false;
  }
}

function isGraphQLResponse(body: string): boolean {
  try {
    const parsed = JSON.parse(body) as GraphQLResponse;

    if (typeof parsed !== "object" || parsed === null) {
      return false;
    }

    const hasData = "data" in parsed;
    const hasErrors =
      "errors" in parsed &&
      Array.isArray(parsed.errors) &&
      parsed.errors.length > 0;

    return hasData || hasErrors;
  } catch {
    return false;
  }
}

function isGraphQLPath(path: string): boolean {
  return GRAPHQL_PATH_PATTERNS.some((pattern) => pattern.test(path));
}

function hasGraphQLIndicators(target: ScanTarget): boolean {
  const { request, response } = target;

  if (response === undefined) {
    return false;
  }

  const method = request.getMethod().toUpperCase();
  if (method === "OPTIONS") {
    return false;
  }

  const path = request.getPath();
  const requestBody = request.getBody()?.toText();
  const responseBody = response.getBody()?.toText();

  const hasGraphQLPathIndicator = isGraphQLPath(path);
  const hasGraphQLRequestBody =
    requestBody !== undefined && isGraphQLRequest(requestBody);
  const hasGraphQLResponseBody =
    responseBody !== undefined && isGraphQLResponse(responseBody);

  if (hasGraphQLPathIndicator) {
    return true;
  }

  if (hasGraphQLRequestBody) {
    return true;
  }

  if (hasGraphQLResponseBody && hasGraphQLRequestBody) {
    return true;
  }

  return false;
}

export default defineCheck(({ step }) => {
  step("detect", (state, context) => {
    const { request, response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const path = request.getPath();
    const requestBody = request.getBody()?.toText();
    const responseBody = response.getBody()?.toText();

    const hasGraphQLPath = isGraphQLPath(path);
    const hasGraphQLRequestBody =
      requestBody !== undefined && isGraphQLRequest(requestBody);
    const hasGraphQLResponseBody =
      responseBody !== undefined && isGraphQLResponse(responseBody);

    if (!hasGraphQLPath && !hasGraphQLRequestBody && !hasGraphQLResponseBody) {
      return done({ state });
    }

    const indicators: string[] = [];
    if (hasGraphQLPath) {
      indicators.push(`GraphQL-like path: \`${path}\``);
    }
    if (hasGraphQLRequestBody) {
      indicators.push(
        "Request body contains GraphQL structure (operationName/query)",
      );
    }
    if (hasGraphQLResponseBody) {
      indicators.push("Response body matches GraphQL structure (data/errors)");
    }

    return done({
      state,
      findings: [
        {
          name: "GraphQL Endpoint Discovered",
          description: `A GraphQL endpoint has been identified based on the following indicators:\n\n${indicators.map((i) => `- ${i}`).join("\n")}\n\nUnlike REST APIs, GraphQL servers operate on a single endpoint. All messages are sent to this endpoint, with the body of the message determining how the server handles the request.\n\nA publicly-available endpoint does not necessarily present a security vulnerability in and of itself. However, this information can still be valuable to attackers, as by definition any attacks on the GraphQL server will use the endpoint discovered. For example, an attacker could then attempt to run an introspection query against the endpoint, which could reveal the entire GraphQL schema if successful.\n\n**Recommendation:**\n- Disable introspection on your GraphQL server when deploying to production\n- Ensure your GraphQL endpoint is only available over the POST HTTP method`,
          severity: Severity.INFO,
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
      id: "graphql-endpoint",
      name: "GraphQL Endpoint Discovered",
      description:
        "Detects GraphQL endpoints by analyzing URL patterns, request body structure (operationName/query), and response structure (data/errors)",
      type: "passive",
      tags: [Tags.GRAPHQL, Tags.ATTACK_SURFACE],
      severities: [Severity.INFO],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    initState: () => ({}),
    when: (target) =>
      target.response !== undefined &&
      target.response.getCode() >= 200 &&
      target.response.getCode() < 500 &&
      hasGraphQLIndicators(target),
  };
});
