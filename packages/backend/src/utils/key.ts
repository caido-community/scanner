import { type ScanTarget } from "engine";

type KeyFn = (ctx: ScanTarget) => string;

type KeyStrategy = {
  withHost: () => KeyStrategy;
  withPort: () => KeyStrategy;
  withPath: () => KeyStrategy;
  withBasePath: () => KeyStrategy;
  withMethod: () => KeyStrategy;
  withQuery: () => KeyStrategy;
  withQueryKeys: () => KeyStrategy;
  build: () => KeyFn;
};

export function getBasePath(path: string): string {
  return path.split("/").slice(0, -1).join("/");
}

export const keyStrategy = (): KeyStrategy => {
  const parts: KeyFn[] = [];

  const add = (part: KeyFn): KeyStrategy => {
    parts.push(part);
    return builder;
  };

  const builder: KeyStrategy = {
    withHost: () => add((ctx) => ctx.request.getHost().toLowerCase()),
    withPort: () => add((ctx) => String(ctx.request.getPort())),
    withPath: () => add((ctx) => ctx.request.getPath()),
    withBasePath: () =>
      add((ctx) => ctx.request.getPath().split("/").slice(0, -1).join("/")),
    withMethod: () => add((ctx) => ctx.request.getMethod().toUpperCase()),
    withQuery: () => add((ctx) => ctx.request.getQuery()),
    withQueryKeys: () =>
      add((ctx) =>
        Array.from(new URLSearchParams(ctx.request.getQuery()).keys())
          .sort()
          .join(","),
      ),
    build: () => (ctx: ScanTarget) => parts.map((fn) => fn(ctx)).join("::"),
  };

  return builder;
};
