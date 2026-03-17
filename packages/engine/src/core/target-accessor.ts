import type { TargetAccessor } from "../types/check-v2";
import type { ScanTarget } from "../types/runner";

/**
 * Wraps a raw scan target with convenience helpers used by V2 checks.
 *
 * V2 checks use this through `ctx.target` for common checks like request method,
 * response header lookup, response body text, and whether the target has parameters.
 */
export function createTargetAccessor(target: ScanTarget): TargetAccessor {
  return {
    ...target,

    hasParameters(): boolean {
      const { request } = target;
      const queryString = request.getQuery();
      const hasQueryParams =
        queryString !== undefined && queryString.length > 0;
      const hasBody = request.getBody() !== undefined;
      return hasQueryParams || hasBody;
    },

    hasBody(): boolean {
      return target.request.getBody() !== undefined;
    },

    isMethod(...methods: string[]): boolean {
      const requestMethod = target.request.getMethod().toUpperCase();
      return methods.some((m) => m.toUpperCase() === requestMethod);
    },

    header(name: string): string | undefined {
      const normalizedName = name.toLowerCase();
      const headers = target.response?.getHeaders();
      if (headers === undefined) return undefined;

      for (const [key, values] of Object.entries(headers)) {
        if (key.toLowerCase() === normalizedName) {
          return values[0];
        }
      }
      return undefined;
    },

    bodyText(): string | undefined {
      return target.response?.getBody()?.toText();
    },
  };
}
