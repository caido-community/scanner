import { type Response } from "caido:utils";

import { type CheckContext } from "../types";

/**
 * A type guard that checks if the context includes a response.
 * Narrows the type of `context.response` to `Response`.
 */
export const hasResponse = (
  context: CheckContext,
): context is CheckContext & { response: Response } => {
  return context.response !== undefined;
};

/**
 * Checks if the request has any query parameters.
 */
export const hasQueryParameters = (context: CheckContext): boolean => {
  return context.request.getQuery().length > 0;
};

/**
 * Returns a function that checks if the request method is a specific value (case-insensitive).
 */
export const requestMethodIs =
  (method: string): ((context: CheckContext) => boolean) =>
  (context) => {
    return context.request.getMethod().toLowerCase() === method.toLowerCase();
  };

/**
 * Returns a function that checks if the request path matches a regular expression.
 */
export const requestPathMatches =
  (pattern: RegExp): ((context: CheckContext) => boolean) =>
  (context) => {
    return pattern.test(context.request.getPath());
  };

/**
 * Returns a function that checks if a specific query parameter exists.
 * The name can be a string for an exact match or a regex for a pattern match.
 */
export const hasQueryParam =
  (name: string | RegExp): ((context: CheckContext) => boolean) =>
  (context) => {
    const params = new URLSearchParams(context.request.getQuery());

    if (typeof name === "string") {
      return params.has(name);
    }

    return Array.from(params.keys()).some((key) => name.test(key));
  };

/**
 * Returns a function that checks if a request header's value contains a given string or matches a regex.
 */
export const requestHeaderMatches =
  (
    headerName: string,
    pattern: string | RegExp,
  ): ((context: CheckContext) => boolean) =>
  (context) => {
    const headerValues = context.request.getHeader(headerName);
    if (!headerValues) return false;

    const predicate =
      typeof pattern === "string"
        ? (v: string) => v.includes(pattern)
        : (v: string) => pattern.test(v);

    return headerValues.some(predicate);
  };

/**
 * Returns a function that checks if the request body contains a given string or matches a regex.
 */
export const requestBodyContains =
  (pattern: string | RegExp): ((context: CheckContext) => boolean) =>
  (context) => {
    const body = context.request.getBody();
    if (!body) return false;

    const bodyText = body.toText();
    return typeof pattern === "string"
      ? bodyText.includes(pattern)
      : pattern.test(bodyText);
  };

/**
 * Returns a function that checks if the response status code is a specific number or within a range.
 */
export const responseStatusCodeIs =
  (
    code: number | { min: number; max: number },
  ): ((context: CheckContext) => boolean) =>
  (context) => {
    if (!hasResponse(context)) return false;

    const statusCode = context.response.getCode();
    if (typeof code === "number") {
      return statusCode === code;
    }
    return statusCode >= code.min && statusCode <= code.max;
  };

/**
 * Returns a function that checks if a response header's value contains a given string or matches a regex.
 */
export const responseHeaderMatches =
  (
    headerName: string,
    pattern: string | RegExp,
  ): ((context: CheckContext) => boolean) =>
  (context) => {
    if (!hasResponse(context)) return false;

    const headerValues = context.response.getHeader(headerName);
    if (!headerValues) return false;

    const predicate =
      typeof pattern === "string"
        ? (v: string) => v.includes(pattern)
        : (v: string) => pattern.test(v);

    return headerValues.some(predicate);
  };

/**
 * Returns a function that checks if the response body contains a given string or matches a regex.
 */
export const responseBodyContains =
  (pattern: string | RegExp): ((context: CheckContext) => boolean) =>
  (context) => {
    if (!hasResponse(context)) return false;

    const body = context.response.getBody();
    if (!body) return false;

    const bodyText = body.toText();
    return typeof pattern === "string"
      ? bodyText.includes(pattern)
      : pattern.test(bodyText);
  };

/**
 * Returns a function that checks if the response 'Content-Type' header matches a given string or regex.
 */
export const responseMimeTypeIs = (
  mimeType: string | RegExp,
): ((context: CheckContext) => boolean) => {
  return responseHeaderMatches("Content-Type", mimeType);
};
