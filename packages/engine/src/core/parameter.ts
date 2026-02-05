import type { Request, RequestSpec } from "caido:utils";

import type { Parameter } from "../types/check-v2";

type ContentType = "json" | "form" | "other";

function getContentType(headers: Record<string, Array<string>>): ContentType {
  const contentTypeHeaders = headers["Content-Type"] ?? headers["content-type"];
  const contentType = contentTypeHeaders?.[0]?.toLowerCase();

  if (contentType === undefined) {
    return "other";
  }

  if (contentType.includes("application/json")) {
    return "json";
  }

  if (contentType.includes("application/x-www-form-urlencoded")) {
    return "form";
  }

  return "other";
}

function parseJsonBody(body: string): Record<string, unknown> | undefined {
  try {
    return JSON.parse(body) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

function extractQueryParameters(
  queryString: string,
): Array<{ name: string; value: string }> {
  const parameters: Array<{ name: string; value: string }> = [];
  const urlParams = new URLSearchParams(queryString);

  for (const [name, value] of urlParams.entries()) {
    if (name !== "") {
      parameters.push({ name, value });
    }
  }

  return parameters;
}

function extractBodyParameters(
  body: string,
  contentType: ContentType,
): Array<{ name: string; value: string }> {
  const parameters: Array<{ name: string; value: string }> = [];

  if (contentType === "form") {
    const bodyParams = new URLSearchParams(body);
    for (const [name, value] of bodyParams.entries()) {
      if (name !== "") {
        parameters.push({ name, value });
      }
    }
  } else if (contentType === "json") {
    const bodyParams = parseJsonBody(body);
    if (bodyParams !== undefined) {
      for (const [name, value] of Object.entries(bodyParams)) {
        if (name !== undefined && value !== undefined) {
          const stringValue =
            typeof value === "string" ? value : JSON.stringify(value);
          parameters.push({ name, value: stringValue });
        }
      }
    }
  }

  return parameters;
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
        const queryString = requestSpec.getQuery();
        const urlParams = new URLSearchParams(queryString);
        urlParams.set(name, newValue);
        requestSpec.setQuery(urlParams.toString());
        break;
      }
      case "body": {
        const body = requestSpec.getBody()?.toText();
        if (body === undefined) {
          return requestSpec;
        }

        const contentType = getContentType(requestSpec.getHeaders());

        if (contentType === "json") {
          const bodyParams = parseJsonBody(body);
          if (bodyParams !== undefined) {
            bodyParams[name] = newValue as unknown;
            requestSpec.setBody(JSON.stringify(bodyParams));
          }
        } else {
          const bodyParams = new URLSearchParams(body);
          bodyParams.set(name, newValue);
          requestSpec.setBody(bodyParams.toString());
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

  const queryString = request.getQuery();
  if (queryString !== undefined && queryString !== "") {
    for (const { name, value } of extractQueryParameters(queryString)) {
      parameters.push({
        name,
        value,
        source: "query",
        inject: createInject({ baseRequest: request, name, source: "query" }),
      });
    }
  }

  const requestBody = request.getBody();
  if (
    request.getMethod().toUpperCase() !== "GET" &&
    requestBody !== undefined
  ) {
    const body = requestBody.toText();
    if (body !== undefined) {
      const contentType = getContentType(request.getHeaders());
      for (const { name, value } of extractBodyParameters(body, contentType)) {
        parameters.push({
          name,
          value,
          source: "body",
          inject: createInject({ baseRequest: request, name, source: "body" }),
        });
      }
    }
  }

  if (options.reflected === true && options.responseBody !== undefined) {
    return parameters.filter((parameter) =>
      options.responseBody!.includes(parameter.value),
    );
  }

  return parameters;
}
