import {
  type CheckContext,
  defineCheckV2,
  generateRandomString,
  Result,
  type ScanTarget,
  Severity,
} from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

type CssReflectionContextKind =
  | "style-tag"
  | "style-attribute"
  | "class-attribute";

type CssReflectionContext = {
  kind: CssReflectionContextKind;
  tagName: string;
};

type CssReflectionProbe = {
  name: string;
  buildPayload: (input: { styleNeedle: string; classToken: string }) => string;
  expectedContexts: CssReflectionContextKind[];
};

const CSS_REFLECTION_PROBES: CssReflectionProbe[] = [
  {
    name: "style context append",
    buildPayload: ({ styleNeedle }) => `;${styleNeedle}`,
    expectedContexts: ["style-tag", "style-attribute"],
  },
  {
    name: "class context append",
    buildPayload: ({ classToken }) => ` ${classToken}`,
    expectedContexts: ["class-attribute"],
  },
];

const PARAMETER_LIMITS = {
  low: 2,
  medium: 5,
  high: 10,
} as const;

const PROBE_LIMITS = {
  low: 1,
  medium: 2,
  high: 2,
} as const;

const isHtmlContentType = (contentType: string | undefined): boolean => {
  return (
    contentType !== undefined && contentType.toLowerCase().includes("html")
  );
};

const hasRenderableHtmlResponse = ({
  code,
  contentType,
}: {
  code: number;
  contentType: string | undefined;
}): boolean => {
  return code === 200 && isHtmlContentType(contentType);
};

const hasTargetParameters = (target: ScanTarget): boolean => {
  return (
    target.request.getQuery() !== "" || target.request.getBody() !== undefined
  );
};

const createReflectionMarker = (originalBody: string): string => {
  let marker = generateRandomString(10).toLowerCase();
  let attempts = 0;

  while (originalBody.includes(marker) && attempts < 5) {
    marker = generateRandomString(10).toLowerCase();
    attempts++;
  }

  return marker;
};

const contextPriority: Record<CssReflectionContextKind, number> = {
  "style-tag": 2,
  "style-attribute": 2,
  "class-attribute": 1,
};

const getSeverityFromContexts = (
  contexts: CssReflectionContext[],
): (typeof Severity)[keyof typeof Severity] => {
  const highestPriority = contexts.reduce((max, current) => {
    return Math.max(max, contextPriority[current.kind]);
  }, 0);

  if (highestPriority >= 2) {
    return Severity.MEDIUM;
  }

  return Severity.LOW;
};

const formatContextLabel = (context: CssReflectionContext): string => {
  if (context.kind === "style-tag") {
    return "<style> element";
  }

  if (context.kind === "style-attribute") {
    return `<${context.tagName}> style attribute`;
  }

  return `<${context.tagName}> class attribute`;
};

const collectCssReflectionContexts = async ({
  ctx,
  requestID,
  styleNeedle,
  classToken,
}: {
  ctx: CheckContext;
  requestID: string;
  styleNeedle: string;
  classToken: string;
}): Promise<CssReflectionContext[]> => {
  const html = await ctx.runtime.html.parse(requestID);
  const contexts: CssReflectionContext[] = [];

  const styleElements = html.findElements({ tagName: "style" });
  for (const styleElement of styleElements) {
    const styleContent = html.getElementText(styleElement);
    if (styleContent.includes(styleNeedle)) {
      contexts.push({
        kind: "style-tag",
        tagName: "style",
      });
    }
  }

  const allElements = html.findElements({});
  for (const element of allElements) {
    const styleAttribute = html.getElementAttribute(element, "style");
    if (styleAttribute !== undefined && styleAttribute.includes(styleNeedle)) {
      contexts.push({
        kind: "style-attribute",
        tagName: element.name,
      });
    }

    const classAttribute = html.getElementAttribute(element, "class");
    if (classAttribute === undefined) {
      continue;
    }

    const classTokens = classAttribute
      .split(/\s+/)
      .filter((token) => token !== "");
    if (classTokens.includes(classToken)) {
      contexts.push({
        kind: "class-attribute",
        tagName: element.name,
      });
    }
  }

  return contexts;
};

export default defineCheckV2({
  id: "reflected-css-injection",
  name: "Reflected CSS Injection",
  description:
    "Detects reflected CSS injection where user-controlled input is injected into style tags, style attributes, or class attributes.",
  type: "active",
  tags: [Tags.CSS_INJECTION, Tags.INJECTION, Tags.INPUT_VALIDATION],
  severities: [Severity.MEDIUM, Severity.LOW],
  aggressivity: {
    minRequests: 1,
    maxRequests: "Infinity",
  },
  dedupeKey: keyStrategy()
    .withMethod()
    .withHost()
    .withPort()
    .withPath()
    .withQueryKeys()
    .build(),
  when: (target) => {
    if (!hasTargetParameters(target)) {
      return false;
    }

    const response = target.response;
    if (response === undefined) {
      return false;
    }

    return hasRenderableHtmlResponse({
      code: response.getCode(),
      contentType: response.getHeader("content-type")?.[0],
    });
  },
  async execute(ctx) {
    if (!ctx.target.hasParameters()) {
      return;
    }

    const originalBody = ctx.target.bodyText();
    if (originalBody === undefined) {
      return;
    }

    const reflectedParameters = ctx.parameters({ reflected: true });
    if (reflectedParameters.length === 0) {
      return;
    }

    const parameters = ctx.limit(reflectedParameters, PARAMETER_LIMITS);
    const probes = ctx.limit(CSS_REFLECTION_PROBES, PROBE_LIMITS);

    for (const parameter of parameters) {
      for (const probe of probes) {
        const marker = createReflectionMarker(originalBody);
        const styleNeedle = `scanner-css-${marker}.invalid`;
        const classToken = `scanner-css-${marker}`;
        const payloadSuffix = probe.buildPayload({ styleNeedle, classToken });
        const injectedValue = `${parameter.value}${payloadSuffix}`;

        const result = await ctx.send(parameter.inject(injectedValue));
        if (Result.isErr(result)) {
          continue;
        }

        const { request, response } = result.value;
        if (
          !hasRenderableHtmlResponse({
            code: response.getCode(),
            contentType: response.getHeader("content-type")?.[0],
          })
        ) {
          continue;
        }

        let allContexts: CssReflectionContext[] = [];
        try {
          allContexts = await collectCssReflectionContexts({
            ctx,
            requestID: request.getId(),
            styleNeedle,
            classToken,
          });
        } catch {
          continue;
        }

        const matchedContexts = allContexts.filter((context) =>
          probe.expectedContexts.includes(context.kind),
        );
        if (matchedContexts.length === 0) {
          continue;
        }

        const contextLabels = Array.from(
          new Set(matchedContexts.map(formatContextLabel)),
        );

        ctx.finding({
          name: `Reflected CSS Injection in parameter '${parameter.name}'`,
          severity: getSeverityFromContexts(matchedContexts),
          description: `Parameter \`${parameter.name}\` from ${parameter.source} is reflected into CSS-executable HTML contexts (${contextLabels.join(", ")}), allowing attacker-controlled styling input to be injected.`,
          impact:
            "Attackers can manipulate rendered styles, potentially enabling UI redressing and CSS-based data exfiltration techniques.",
          recommendation:
            "Apply strict output encoding for CSS contexts, validate allowed values with a safe allowlist, and avoid reflecting raw user input inside style or class-related HTML contexts.",
          artifacts: {
            title: "Detection details",
            items: [
              `Parameter: ${parameter.name} (${parameter.source})`,
              `Probe: ${probe.name}`,
              `Payload suffix: ${payloadSuffix}`,
              `Contexts: ${contextLabels.join(", ")}`,
            ],
          },
          request,
        });
        return;
      }
    }
  },
});
