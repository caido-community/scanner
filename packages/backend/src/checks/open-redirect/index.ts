import { type Request } from "caido:utils";
import {
  createUrlBypassGenerator,
  defineCheckV2,
  findRedirection,
  Result,
  Severity,
} from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

const KEYWORDS = [
  "url",
  "redirect",
  "target",
  "destination",
  "return",
  "path",
  "next",
];

const ATTACKER_HOST = "scanner-attacker.invalid";

function isSuspiciousRedirectParam(name: string, value: string): boolean {
  const keyLower = name.toLowerCase();
  const hasKeywordInName = KEYWORDS.some((keyword) =>
    keyLower.includes(keyword),
  );
  const hasUrlInValue =
    value.startsWith("http://") ||
    value.startsWith("https://") ||
    value.startsWith("/");
  return hasKeywordInName || hasUrlInValue;
}

export function getSuspiciousParamsFromQuery(query: string): string[] {
  const params = new URLSearchParams(query);
  return Array.from(params.keys()).filter((key) => {
    const value = params.get(key) ?? "";
    return isSuspiciousRedirectParam(key, value);
  });
}

export function getExpectedHostInfo(
  request: Request,
  paramValue: string | undefined,
): { host: string; protocol: string } {
  if (paramValue !== undefined && paramValue.startsWith("http")) {
    try {
      const url = new URL(paramValue);
      return { host: url.host, protocol: url.protocol };
    } catch {
      return getExpectedHostInfo(request, undefined);
    }
  }

  const host = request.getHost();
  const port = request.getPort();
  const protocol = new URL(request.getUrl()).protocol;
  const expectedHost = port === 80 || port === 443 ? host : `${host}:${port}`;

  return { host: expectedHost, protocol };
}

export default defineCheckV2({
  id: "open-redirect",
  name: "Open Redirect",
  description:
    "Checks for open redirects using a variety of URL parser bypass techniques",
  type: "active",
  tags: [Tags.OPEN_REDIRECT],
  severities: [Severity.MEDIUM],
  aggressivity: {
    minRequests: 1,
    maxRequests: "Infinity",
  },
  dedupeKey: keyStrategy()
    .withMethod()
    .withHost()
    .withPort()
    .withPath()
    .build(),
  when: (target) => {
    const query = target.request.getQuery();
    if (query === undefined || query === "") return false;
    return getSuspiciousParamsFromQuery(query).length > 0;
  },

  async execute(ctx) {
    const params = ctx
      .parameters()
      .filter((param) => isSuspiciousRedirectParam(param.name, param.value));
    if (params.length === 0) return;

    for (const param of params) {
      const { host: expectedHost, protocol } = getExpectedHostInfo(
        ctx.target.request,
        param.value,
      );

      const generatorResult = createUrlBypassGenerator({
        expectedHost,
        attackerHost: ATTACKER_HOST,
        originalValue: param.value,
        protocol,
      });

      if (Result.isErr(generatorResult)) continue;

      const allPayloadRecipes = [...generatorResult.value];
      const payloadRecipes = ctx.limit(allPayloadRecipes, {
        low: 2,
        medium: 5,
        high: allPayloadRecipes.length,
      });

      for (const payloadRecipe of payloadRecipes) {
        const instance = payloadRecipe.generate();
        const spec = param.inject(instance.value);

        const result = await ctx.send(spec);
        if (Result.isErr(result)) continue;

        const { request } = result.value;
        const redirectInfo = await findRedirection(request.getId(), ctx);

        if (!redirectInfo.hasRedirection || redirectInfo.location === undefined)
          continue;

        try {
          const redirectUrl = new URL(
            redirectInfo.location,
            ctx.target.request.getUrl(),
          );

          if (instance.validatesWith(redirectUrl)) {
            ctx.finding({
              name: `Open Redirect in parameter '${param.name}'`,
              description: `Parameter \`${param.name}\` allows ${redirectInfo.type} redirect via the \`${payloadRecipe.technique}\` technique.\n\n**Payload used:**\n\`\`\`\n${instance.value}\n\`\`\`\n\n${payloadRecipe.description}`,
              severity: Severity.MEDIUM,
              request,
            });
            return;
          }
        } catch {
          continue;
        }
      }
    }
  },
});
