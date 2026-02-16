import type { Request, RequestSpec } from "caido:utils";
import { HttpForge } from "ts-http-forge";

import type { Parameter } from "../types/check-v2";

type ParsedParameter = { name: string; value: string };

function createRequestForge(request: Request) {
  return HttpForge.create(request.getRaw().toText());
}

function extractQueryParameters(request: Request): ParsedParameter[] {
  const queryParameters = createRequestForge(request).getQueryParams();
  if (queryParameters === null) {
    return [];
  }

  return Object.entries(queryParameters)
    .filter(([name]) => name !== "")
    .map(([name, value]) => ({ name, value }));
}

function extractBodyParameters(request: Request): ParsedParameter[] {
  const bodyParameters = createRequestForge(request).getBodyParams();
  if (bodyParameters === null) {
    return [];
  }
  return Object.entries(bodyParameters)
    .filter(([name]) => name !== "")
    .map(([name, value]) => ({ name, value }));
}

export type InjectOptions = {
  baseRequest: Request;
  name: string;
  source: "query" | "body" | "header";
};

function createInject(
  options: InjectOptions,
): (newValue: string) => RequestSpec {
  const { baseRequest, name, source } = options;

  return (newValue: string): RequestSpec => {
    const requestSpec = baseRequest.toSpec();

    switch (source) {
      case "query": {
        const updatedQuery = createRequestForge(baseRequest)
          .upsertQueryParam(name, newValue)
          .getQuery();
        requestSpec.setQuery(updatedQuery ?? "");
        break;
      }
      case "body": {
        const body = baseRequest.getBody()?.toText();
        if (body === undefined) {
          return requestSpec;
        }

        const updatedRequest = createRequestForge(baseRequest).setBodyParam(
          name,
          newValue,
        );
        const updatedBody = updatedRequest.getBody();
        if (updatedBody !== null) {
          requestSpec.setBody(updatedBody);
        }
        break;
      }
      case "header": {
        requestSpec.setHeader(name, newValue);
        break;
      }
    }

    return requestSpec;
  };
}

export function extractParameters(
  request: Request,
  options: { reflected?: boolean; responseBody?: string } = {},
): Parameter[] {
  const parameters: Parameter[] = [];

  for (const { name, value } of extractQueryParameters(request)) {
    parameters.push({
      name,
      value,
      source: "query",
      inject: createInject({ baseRequest: request, name, source: "query" }),
    });
  }

  const requestBody = request.getBody();
  if (
    request.getMethod().toUpperCase() !== "GET" &&
    requestBody !== undefined
  ) {
    for (const { name, value } of extractBodyParameters(request)) {
      parameters.push({
        name,
        value,
        source: "body",
        inject: createInject({ baseRequest: request, name, source: "body" }),
      });
    }
  }

  const responseBody = options.responseBody;
  if (options.reflected === true && responseBody !== undefined) {
    return parameters.filter((parameter) =>
      responseBody.includes(parameter.value),
    );
  }

  return parameters;
}
