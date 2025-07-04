import { type Request } from "caido:utils";
import {
  continueWith,
  createUrlBypassGenerator,
  defineCheck,
  done,
  findRedirection,
  ScanStrength,
  Severity,
} from "engine";

const keywords = [
  "url",
  "redirect",
  "target",
  "destination",
  "return",
  "path",
  "next",
];

const getUrlParams = (query: string): string[] => {
  const params = new URLSearchParams(query);

  // @ts-expect-error - TODO: figure out TS throwing here for .keys()
  return Array.from(params.keys()).filter((key: string) => {
    const keyLower = key.toLowerCase();
    const value = params.get(key) ?? "";

    const hasKeywordInName = keywords.some((keyword) =>
      keyLower.includes(keyword),
    );
    const hasUrlInValue =
      value.startsWith("http://") ||
      value.startsWith("https://") ||
      value.startsWith("/");

    return hasKeywordInName || hasUrlInValue;
  });
};

const getExpectedHostInfo = (
  request: Request,
  paramValue: string | undefined,
): {
  host: string;
  protocol: string;
} => {
  if (paramValue !== undefined && paramValue.startsWith("http")) {
    try {
      const url = new URL(paramValue);
      return { host: url.host, protocol: url.protocol };
    } catch {
      // Ignore invalid URLs and fallback to using the request's host
    }
  }

  const host = request.getHost();
  const port = request.getPort();
  const protocol = new URL(request.getUrl()).protocol;
  const expectedHost = port === 80 || port === 443 ? host : `${host}:${port}`;

  return { host: expectedHost, protocol };
};

export default defineCheck<{
  urlParams: string[];
}>(({ step }) => {
  step("findUrlParams", (_, context) => {
    const query = context.target.request.getQuery();
    const urlParams = getUrlParams(query);

    if (urlParams.length === 0) {
      return done();
    }

    return continueWith({
      nextStep: "testParam",
      state: { urlParams },
    });
  });

  step("testParam", async (state, context) => {
    if (state.urlParams.length === 0) {
      return done();
    }

    const [currentParam, ...remainingParams] = state.urlParams;
    if (currentParam === undefined) {
      return done();
    }

    const attackerHost = "example.com";

    const originalQueryForParamValue = context.target.request.getQuery() || "";
    const paramsForParamValue = new URLSearchParams(originalQueryForParamValue);
    const paramValue = paramsForParamValue.get(currentParam) ?? undefined;

    const { host: expectedHost, protocol } = getExpectedHostInfo(
      context.target.request,
      paramValue,
    );

    let generator = createUrlBypassGenerator({
      expectedHost,
      attackerHost,
      protocol,
    });

    if (context.config.strength === ScanStrength.LOW) {
      generator = generator.limit(2);
    } else if (context.config.strength === ScanStrength.MEDIUM) {
      generator = generator.limit(5);
    }

    for (const payloadRecipe of generator) {
      const instance = payloadRecipe.generate();

      const originalQuery = context.target.request.getQuery() || "";
      const params = new URLSearchParams(originalQuery);
      params.set(currentParam, instance.value);

      const spec = context.target.request.toSpec();
      spec.setQuery(params.toString());

      const { request, response } = await context.sdk.requests.send(spec);
      const redirectInfo = findRedirection(response, context);
      if (redirectInfo.hasRedirection && redirectInfo.location) {
        try {
          const redirectUrl = new URL(
            redirectInfo.location,
            context.target.request.getUrl(),
          );
          if (instance.validatesWith(redirectUrl)) {
            context.sdk.console.log("found finding");
            return done({
              findings: [
                {
                  name: "Open Redirect",
                  description: `Parameter \`${currentParam}\` allows ${redirectInfo.type} redirect via the \`${payloadRecipe.technique}\` technique.\n\n**Payload used:**\n\`\`\`\n${instance.value}\n\`\`\`\n\n${payloadRecipe.description}`,
                  severity: Severity.MEDIUM,
                  correlation: {
                    requestID: request.getId(),
                    locations: [],
                  },
                },
              ],
            });
          }
        } catch {
          // TODO: we might wanna log this somewhere as this is definitely a interesting finding
          // Ignore invalid redirect URLs
        }
      }
    }

    return continueWith({
      nextStep: "testParam",
      state: {
        ...state,
        urlParams: remainingParams,
      },
    });
  });

  return {
    metadata: {
      id: "open-redirect",
      name: "Open Redirect",
      description:
        "Checks for open redirects using a variety of URL parser bypass techniques.",
      type: "active",
      tags: ["open-redirect"],
      aggressivity: {
        minRequests: 1,
        maxRequests: "Infinity",
      },
    },

    initState: () => ({ urlParams: [] }),
    dedupeKey: (context) => {
      return (
        context.request.getHost() +
        context.request.getPort() +
        context.request.getPath()
      );
    },
    when: (context) => {
      const query = context.request.getQuery();
      if (!query) return false;

      return getUrlParams(query).length > 0;
    },
  };
});
