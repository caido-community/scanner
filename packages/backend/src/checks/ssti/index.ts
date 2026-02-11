import {
  continueWith,
  defineCheck,
  done,
  ScanAggressivity,
  Severity,
} from "engine";

import { Tags } from "../../types";
import { extractReflectedParameters, type Parameter } from "../../utils";
import { keyStrategy } from "../../utils/key";

const MARKER = "__ssti_probe__";

type State = {
  testParams: Parameter[];
  currentParamIndex: number;
  currentPayloadIndex: number;
};

type PayloadConfig = {
  payload: string;
  expected: string;
  description: string;
};

type ErrorPayloadConfig = {
  payload: string;
  description: string;
};

const MATH_PAYLOADS: PayloadConfig[] = [
  {
    payload: "{{1234*5678}}",
    expected: "7006652",
    description: "Double curly brace mathematical expression",
  },
  {
    payload: "${1234*5678}",
    expected: "7006652",
    description: "Dollar brace mathematical expression",
  },
  {
    payload: "<%= 1234*5678 %>",
    expected: "7006652",
    description: "ERB mathematical expression",
  },
  {
    payload: "{1234*5678}",
    expected: "7006652",
    description: "Smarty mathematical expression",
  },
  {
    payload: "[[${1234*5678}]]",
    expected: "7006652",
    description: "Thymeleaf mathematical expression",
  },
];

const ERROR_PAYLOADS: ErrorPayloadConfig[] = [
  {
    payload: "{{7*'7'}}",
    description: "Type mismatch error in double curly braces",
  },
  {
    payload: "${7*'7'}",
    description: "Type mismatch error in dollar braces",
  },
  {
    payload: "<%= 7*'7' %>",
    description: "Type mismatch error in ERB",
  },
  {
    payload: "{{undefined_var}}",
    description: "Undefined variable error in double curly braces",
  },
  {
    payload: "${undefined_var}",
    description: "Undefined variable error in dollar braces",
  },
  {
    payload: "{{7*}}",
    description: "Syntax error in double curly braces",
  },
];

const TEMPLATE_ERROR_SIGNATURES = [
  "jinja2.exceptions.TemplateSyntaxError",
  "jinja2.exceptions.UndefinedError",
  "TemplateSyntaxError",
  "UndefinedError",
  "Twig_Error_Syntax",
  "Twig_Error_Runtime",
  "Unexpected character",
  "Unknown filter",
  "freemarker.template.TemplateException",
  "freemarker.core.InvalidReferenceException",
  "FreeMarker template error",
  "Smarty_Compiler_Exception",
  "Smarty: Syntax error",
  "Smarty error",
  "ActionView::Template::Error",
  "ERB::Util",
  "erb template",
  "template syntax error",
  "template compilation error",
  "template parse error",
];

function getMathPayloadsForAggressivity(
  aggressivity: ScanAggressivity,
): PayloadConfig[] {
  switch (aggressivity) {
    case ScanAggressivity.LOW:
      return MATH_PAYLOADS.slice(0, 2);
    case ScanAggressivity.MEDIUM:
      return MATH_PAYLOADS;
    case ScanAggressivity.HIGH:
      return MATH_PAYLOADS;
    default:
      return MATH_PAYLOADS.slice(0, 2);
  }
}

function getErrorPayloadsForAggressivity(
  aggressivity: ScanAggressivity,
): ErrorPayloadConfig[] {
  switch (aggressivity) {
    case ScanAggressivity.LOW:
      return ERROR_PAYLOADS.slice(0, 1);
    case ScanAggressivity.MEDIUM:
      return ERROR_PAYLOADS.slice(0, 3);
    case ScanAggressivity.HIGH:
      return ERROR_PAYLOADS;
    default:
      return ERROR_PAYLOADS.slice(0, 1);
  }
}

function detectMathematicalEvaluation(
  response: string,
  expectedResult: string,
  originalValue: string,
  payload: string,
  marker: string,
): boolean {
  const cleanResponse = response.trim();
  const payloadPattern = originalValue + marker + payload;
  const hasPayloadPattern = cleanResponse.includes(payloadPattern);
  if (hasPayloadPattern) {
    return false;
  }

  const resultPattern = originalValue + marker + expectedResult;

  return (
    cleanResponse.includes(resultPattern) &&
    !cleanResponse.includes(payloadPattern)
  );
}

function detectTemplateError(response: string): string | undefined {
  for (const signature of TEMPLATE_ERROR_SIGNATURES) {
    if (response.includes(signature)) {
      return signature;
    }
  }
  return undefined;
}

export default defineCheck<State>(({ step }) => {
  step("findReflectedParameters", (state, context) => {
    const testParams = extractReflectedParameters(context);

    if (testParams.length === 0) {
      return done({ state });
    }

    return continueWith({
      nextStep: "testMathematicalPayloads",
      state: {
        ...state,
        testParams,
        currentParamIndex: 0,
        currentPayloadIndex: 0,
      },
    });
  });

  step("testMathematicalPayloads", async (state, context) => {
    const mathPayloads = getMathPayloadsForAggressivity(
      context.config.aggressivity,
    );

    if (
      state.currentParamIndex >= state.testParams.length ||
      state.currentPayloadIndex >= mathPayloads.length
    ) {
      return continueWith({
        nextStep: "testErrorPayloads",
        state: {
          ...state,
          currentParamIndex: 0,
          currentPayloadIndex: 0,
        },
      });
    }

    const currentParam = state.testParams[state.currentParamIndex];
    const currentPayload = mathPayloads[state.currentPayloadIndex];

    if (currentParam === undefined || currentPayload === undefined) {
      return done({ state });
    }

    try {
      const testValue = currentParam.value + MARKER + currentPayload.payload;
      const requestSpec = currentParam.inject(testValue);

      const { request, response } =
        await context.sdk.requests.send(requestSpec);

      if (response !== undefined) {
        const responseBody = response.getBody()?.toText();

        if (responseBody !== undefined) {
          if (
            detectMathematicalEvaluation(
              responseBody,
              currentPayload.expected,
              currentParam.value,
              currentPayload.payload,
              MARKER,
            )
          ) {
            return done({
              findings: [
                {
                  name: `Server-Side Template Injection in parameter '${currentParam.name}'`,
                  description: `Parameter \`${currentParam.name}\` in ${currentParam.source} is vulnerable to Server-Side Template Injection. Mathematical expression evaluation was detected, indicating template processing of user input.\n\n**Payload used:**\n\`\`\`\n${currentPayload.payload}\n\`\`\`\n\n**Expected result:** \`${currentPayload.expected}\`\n**Detection method:** ${currentPayload.description}\n\n⚠️ **Critical Impact:** This vulnerability can lead to Remote Code Execution (RCE), full server compromise, and unauthorized access to sensitive data.`,
                  severity: Severity.CRITICAL,
                  correlation: {
                    requestID: request.getId(),
                    locations: [],
                  },
                },
              ],
              state,
            });
          }
        }
      }
    } catch {
      // Continue with next payload on error
    }

    const nextPayloadIndex = state.currentPayloadIndex + 1;
    const nextParamIndex =
      nextPayloadIndex >= mathPayloads.length
        ? state.currentParamIndex + 1
        : state.currentParamIndex;
    const resetPayloadIndex =
      nextPayloadIndex >= mathPayloads.length ? 0 : nextPayloadIndex;

    return continueWith({
      nextStep: "testMathematicalPayloads",
      state: {
        ...state,
        currentParamIndex: nextParamIndex,
        currentPayloadIndex: resetPayloadIndex,
      },
    });
  });

  step("testErrorPayloads", async (state, context) => {
    const errorPayloads = getErrorPayloadsForAggressivity(
      context.config.aggressivity,
    );

    if (
      state.currentParamIndex >= state.testParams.length ||
      state.currentPayloadIndex >= errorPayloads.length
    ) {
      return done({
        state: {
          ...state,
          currentParamIndex: 0,
          currentPayloadIndex: 0,
        },
      });
    }

    const currentParam = state.testParams[state.currentParamIndex];
    const currentPayload = errorPayloads[state.currentPayloadIndex];

    if (currentParam === undefined || currentPayload === undefined) {
      return done({ state });
    }

    try {
      const testValue = currentParam.value + currentPayload.payload;
      const requestSpec = currentParam.inject(testValue);

      const { request, response } =
        await context.sdk.requests.send(requestSpec);

      if (response !== undefined) {
        const responseBody = response.getBody()?.toText();

        if (responseBody !== undefined) {
          const errorSignature = detectTemplateError(responseBody);

          if (errorSignature !== undefined) {
            return done({
              findings: [
                {
                  name: `Potential Server-Side Template Injection in parameter '${currentParam.name}'`,
                  description: `Parameter \`${currentParam.name}\` in ${currentParam.source} may be vulnerable to Server-Side Template Injection. Template engine error was detected, suggesting template processing of user input.\n\n**Payload used:**\n\`\`\`\n${currentPayload.payload}\n\`\`\`\n\n**Error signature detected:**\n\`\`\`\n${errorSignature}\n\`\`\`\n\n**Detection method:** ${currentPayload.description}\n\n⚠️ **High Impact:** Template injection vulnerabilities can lead to Remote Code Execution and data exposure. Further manual testing is recommended.`,
                  severity: Severity.HIGH,
                  correlation: {
                    requestID: request.getId(),
                    locations: [],
                  },
                },
              ],
              state,
            });
          }
        }
      }
    } catch {
      // Continue with next payload on error
    }

    const nextPayloadIndex = state.currentPayloadIndex + 1;
    const nextParamIndex =
      nextPayloadIndex >= errorPayloads.length
        ? state.currentParamIndex + 1
        : state.currentParamIndex;
    const resetPayloadIndex =
      nextPayloadIndex >= errorPayloads.length ? 0 : nextPayloadIndex;

    return continueWith({
      nextStep: "testErrorPayloads",
      state: {
        ...state,
        currentParamIndex: nextParamIndex,
        currentPayloadIndex: resetPayloadIndex,
      },
    });
  });

  // context-based step removed

  return {
    metadata: {
      id: "ssti",
      name: "Server-Side Template Injection",
      description:
        "Detects Server-Side Template Injection using mathematical expressions and error signatures",
      type: "active",
      tags: [Tags.SSTI, Tags.INJECTION, Tags.RCE, Tags.TEMPLATE],
      severities: [Severity.CRITICAL, Severity.HIGH],
      aggressivity: {
        minRequests: 1,
        maxRequests: "Infinity",
      },
    },

    initState: () => ({
      testParams: [],
      currentParamIndex: 0,
      currentPayloadIndex: 0,
    }),

    dedupeKey: keyStrategy()
      .withMethod()
      .withHost()
      .withPort()
      .withPath()
      .withQueryKeys()
      .build(),

    when: (target) => {
      const { request } = target;
      const hasQueryParams = request.getQuery() !== "";
      const hasBody = request.getBody() !== undefined;
      return hasQueryParams || hasBody;
    },
  };
});
