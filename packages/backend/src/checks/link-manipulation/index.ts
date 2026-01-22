import { defineCheck, done, type ScanTarget, Severity } from "engine";

import { Tags } from "../../types";
import { extractParameters, keyStrategy, type Parameter } from "../../utils";

type ReflectionType = "full" | "partial";

const HREF_ELEMENTS = ["a", "link", "area", "base"];
const SRC_ELEMENTS = [
  "img",
  "script",
  "iframe",
  "embed",
  "video",
  "audio",
  "source",
  "track",
  "object",
];

type AttributeMatch = {
  tagName: string;
  attribute: "href" | "src";
  value: string;
};

function isExploitable(target: ScanTarget): boolean {
  const { response } = target;

  if (response === undefined) {
    return false;
  }

  const contentType = response.getHeader("Content-Type")?.[0]?.toLowerCase();
  if (contentType !== undefined && !contentType.includes("text/html")) {
    return false;
  }

  const responseBody = response.getBody()?.toText();
  if (responseBody === undefined || responseBody.length === 0) {
    return false;
  }

  return true;
}

function hasMinimumLength(value: string): boolean {
  return value.length >= 5;
}

export default defineCheck(({ step }) => {
  step("analyze", async (state, context) => {
    const parameters = extractParameters(context);

    if (parameters.length === 0) {
      return done({ state });
    }

    const relevantParams = parameters.filter((p) => hasMinimumLength(p.value));
    if (relevantParams.length === 0) {
      return done({ state });
    }

    const html = await context.runtime.html.parse(
      context.target.request.getId(),
    );
    if (html === undefined) {
      return done({ state });
    }

    const attributeMatches: AttributeMatch[] = [];

    for (const tagName of HREF_ELEMENTS) {
      const elements = html.findElements({ tagName });
      for (const element of elements) {
        const hrefValue = html.getElementAttribute(element, "href");
        if (hrefValue !== undefined && hrefValue !== "") {
          attributeMatches.push({
            tagName,
            attribute: "href",
            value: hrefValue,
          });
        }
      }
    }

    for (const tagName of SRC_ELEMENTS) {
      const elements = html.findElements({ tagName });
      for (const element of elements) {
        const srcValue = html.getElementAttribute(element, "src");
        if (srcValue !== undefined && srcValue !== "") {
          attributeMatches.push({
            tagName,
            attribute: "src",
            value: srcValue,
          });
        }
      }
    }

    if (attributeMatches.length === 0) {
      return done({ state });
    }

    const findings = findReflections(relevantParams, attributeMatches, context);
    return done({ state, findings });
  });

  return {
    metadata: {
      id: "link-manipulation",
      name: "Link Manipulation (Reflected)",
      description:
        "Detects when user-supplied input is reflected in href or src attributes, which can lead to phishing attacks, javascript: URL injection, or external resource loading.",
      type: "passive",
      tags: [Tags.INPUT_VALIDATION, Tags.XSS, Tags.OPEN_REDIRECT],
      severities: [Severity.HIGH, Severity.LOW],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    dedupeKey: keyStrategy()
      .withMethod()
      .withHost()
      .withPort()
      .withPath()
      .withQueryKeys()
      .build(),
    initState: () => ({}),
    when: (target) => isExploitable(target),
  };
});

function getReflectionType(
  paramValue: string,
  attributeValue: string,
): ReflectionType | undefined {
  if (!attributeValue.includes(paramValue)) {
    return undefined;
  }

  if (attributeValue === paramValue) {
    return "full";
  }

  return "partial";
}

function findReflections(
  parameters: Parameter[],
  attributeMatches: AttributeMatch[],
  context: { target: { request: { getId: () => string } } },
) {
  const findings: {
    name: string;
    description: string;
    severity: (typeof Severity)[keyof typeof Severity];
    correlation: { requestID: string; locations: never[] };
  }[] = [];

  const reportedParams = new Set<string>();

  for (const param of parameters) {
    for (const match of attributeMatches) {
      const reflectionType = getReflectionType(param.value, match.value);
      if (reflectionType === undefined) {
        continue;
      }

      const paramKey = `${param.name}:${param.source}`;
      if (reportedParams.has(paramKey)) {
        continue;
      }
      reportedParams.add(paramKey);

      const isFullControl = reflectionType === "full";
      const severity = isFullControl ? Severity.HIGH : Severity.LOW;
      const controlDescription = isFullControl
        ? "The parameter value fully controls the attribute value, allowing complete manipulation of the link destination."
        : "The parameter value is partially reflected in the attribute. While exploitation may be limited, it could still enable phishing or redirect attacks depending on the context.";

      findings.push({
        name: `Link Manipulation in parameter '${param.name}'`,
        description: `Parameter \`${param.name}\` from ${param.source} is reflected in the \`${match.attribute}\` attribute of a \`<${match.tagName}>\` element.\n\n**Reflected value:** \`${param.value}\`\n**Found in:** \`<${match.tagName} ${match.attribute}="${truncate(match.value, 100)}">\`\n**Control level:** ${isFullControl ? "Full" : "Partial"}\n\n${controlDescription}\n\nThis can potentially be exploited for:\n- Phishing attacks (manipulating links to external domains)\n- JavaScript URL injection (\`javascript:\` protocol)\n- External resource loading manipulation`,
        severity,
        correlation: {
          requestID: context.target.request.getId(),
          locations: [],
        },
      });
    }
  }

  return findings;
}

function truncate(value: string, maxLength: number): string {
  if (value.length <= maxLength) {
    return value;
  }
  return value.slice(0, maxLength) + "...";
}
