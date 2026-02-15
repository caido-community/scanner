import type { Request, RequestSpec } from "caido:utils";
import type { CheckContext } from "engine";
import { HttpForge } from "ts-http-forge";

type InputVectorKind = "query" | "cookie" | "header";

type InputVector = {
  kind: InputVectorKind;
  name: string;
  createSpec: (marker: string) => RequestSpec;
};

const removeHeaderCaseInsensitive = (spec: RequestSpec, name: string): void => {
  for (const key of Object.keys(spec.getHeaders())) {
    if (key.toLowerCase() === name.toLowerCase()) {
      spec.removeHeader(key);
    }
  }
};

export const createQueryInputVectors = (ctx: CheckContext): InputVector[] => {
  return ctx
    .parameters()
    .filter((param) => param.source === "query")
    .map((param) => ({
      kind: "query",
      name: param.name,
      createSpec: (marker) => param.inject(marker),
    }));
};

export const createCookieInputVectors = (request: Request): InputVector[] => {
  let cookieNames: string[] = [];
  const rawRequest = request.getRaw().toText();

  try {
    const cookies = HttpForge.create(rawRequest).getCookies();
    cookieNames =
      cookies === null
        ? []
        : Object.keys(cookies).filter((name) => name.trim() !== "");
  } catch {
    return [];
  }

  if (cookieNames.length === 0) {
    return [];
  }

  return cookieNames.map((cookieName) => ({
    kind: "cookie",
    name: cookieName,
    createSpec: (marker) => {
      const spec = request.toSpec();

      let cookieHeaderValue: string | undefined = undefined;
      try {
        const headerValue = HttpForge.create(rawRequest)
          .setCookie(cookieName, marker)
          .getHeader("cookie");
        cookieHeaderValue = headerValue === null ? undefined : headerValue;
      } catch {
        cookieHeaderValue = undefined;
      }

      if (cookieHeaderValue === undefined) {
        return spec;
      }

      removeHeaderCaseInsensitive(spec, "cookie");
      spec.setHeader("Cookie", cookieHeaderValue);
      return spec;
    },
  }));
};

type HeaderProbe = {
  name: string;
  buildValue: (marker: string) => string;
};

const BASIC_HEADER_PROBES: HeaderProbe[] = [
  {
    name: "User-Agent",
    buildValue: (marker) => marker,
  },
  {
    name: "Referer",
    buildValue: (marker) => `https://scanner.invalid/${marker}`,
  },
  {
    name: "Origin",
    buildValue: (marker) => `https://${marker}.invalid`,
  },
];

export const createHeaderInputVectors = (request: Request): InputVector[] => {
  return BASIC_HEADER_PROBES.map((probe) => ({
    kind: "header",
    name: probe.name,
    createSpec: (marker) => {
      const spec = request.toSpec();
      removeHeaderCaseInsensitive(spec, probe.name);
      spec.setHeader(probe.name, probe.buildValue(marker));
      return spec;
    },
  }));
};

const assertNever = (value: never): never => {
  throw new Error(`Unhandled input vector kind: ${String(value)}`);
};

export const formatInputVector = (vector: InputVector): string => {
  switch (vector.kind) {
    case "query":
      return `query parameter \`${vector.name}\``;
    case "cookie":
      return `cookie \`${vector.name}\``;
    case "header":
      return `header \`${vector.name}\``;
    default:
      return assertNever(vector.kind);
  }
};
