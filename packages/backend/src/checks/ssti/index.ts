import {
  continueWith,
  defineCheck,
  done,
  ScanAggressivity,
  Severity,
} from "engine";

import {
  createRequestWithParameter,
  extractReflectedParameters,
  type Parameter,
} from "../../utils";

type State = {
  testParams: Parameter[];
  currentParamIndex: number;
  currentPayloadIndex: number;
  detectionPhase: "math" | "error" | "context";
};

type PayloadConfig = {
  payload: string;
  expected: string;
  engines: string[];
  description: string;
};

type ErrorPayloadConfig = {
  payload: string;
  description: string;
};

const MATH_PAYLOADS: PayloadConfig[] = [
  {
    payload: "{{7*7}}",
    expected: "49",
    engines: ["Jinja2", "Twig", "Handlebars"],
    description: "Double curly brace mathematical expression",
  },
  {
    payload: "{{8*8}}",
    expected: "64", 
    engines: ["Jinja2", "Twig", "Handlebars"],
    description: "Double curly brace mathematical expression",
  },
  {
    payload: "{{9*9}}",
    expected: "81",
    engines: ["Jinja2", "Twig", "Handlebars"],
    description: "Double curly brace mathematical expression",
  },
  {
    payload: "${7*7}",
    expected: "49",
    engines: ["FreeMarker", "Velocity"],
    description: "Dollar brace mathematical expression",
  },
  {
    payload: "${8*8}",
    expected: "64",
    engines: ["FreeMarker", "Velocity"],
    description: "Dollar brace mathematical expression",
  },
  {
    payload: "<%= 7*7 %>",
    expected: "49",
    engines: ["ERB"],
    description: "ERB mathematical expression",
  },
  {
    payload: "<%= 8*8 %>", 
    expected: "64",
    engines: ["ERB"],
    description: "ERB mathematical expression",
  },
  {
    payload: "{7*7}",
    expected: "49",
    engines: ["Smarty"],
    description: "Smarty mathematical expression",
  },
  {
    payload: "{8*8}",
    expected: "64",
    engines: ["Smarty"],
    description: "Smarty mathematical expression",
  },
  {
    payload: "[[${7*7}]]",
    expected: "49",
    engines: ["Thymeleaf"],
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

const CONTEXT_PAYLOADS: ErrorPayloadConfig[] = [
  {
    payload: "{{request}}",
    description: "Template request object access",
  },
  {
    payload: "{{self}}",
    description: "Template self reference",
  },
  {
    payload: "{{dump(app)}}",
    description: "Twig application dump",
  },
  {
    payload: "{{config}}",
    description: "Configuration object access",
  },
  {
    payload: "{$smarty.version}",
    description: "Smarty version information",
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

const CONTEXT_INDICATORS = [
  "Request",
  "application",
  "config",
  "smarty",
  "version",
  "server",
  "environment",
  "session",
];

function getMathPayloadsForAggressivity(aggressivity: ScanAggressivity): PayloadConfig[] {
  switch (aggressivity) {
    case ScanAggressivity.LOW:
      return MATH_PAYLOADS.slice(0, 2);
    case ScanAggressivity.MEDIUM:
      return MATH_PAYLOADS.slice(0, 6);
    case ScanAggressivity.HIGH:
      return MATH_PAYLOADS;
    default:
      return MATH_PAYLOADS.slice(0, 2);
  }
}

function getErrorPayloadsForAggressivity(aggressivity: ScanAggressivity): ErrorPayloadConfig[] {
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

function getContextPayloadsForAggressivity(aggressivity: ScanAggressivity): ErrorPayloadConfig[] {
  switch (aggressivity) {
    case ScanAggressivity.LOW:
      return [];
    case ScanAggressivity.MEDIUM:
      return CONTEXT_PAYLOADS.slice(0, 2);
    case ScanAggressivity.HIGH:
      return CONTEXT_PAYLOADS;
    default:
      return [];
  }
}

function detectMathematicalEvaluation(response: string, expectedResult: string, originalValue: string, payload: string): boolean {
  const cleanResponse = response.trim();
  const exactMatch = cleanResponse.includes(expectedResult);
  
  if (!exactMatch) {
    return false;
  }
  
  // Check if the response contains the original value + payload pattern but result is different
  const payloadPattern = originalValue + payload;
  const hasPayloadPattern = cleanResponse.includes(payloadPattern);
  
  // If the payload pattern is still there, it means it wasn't evaluated
  if (hasPayloadPattern) {
    return false;
  }
  
  // More strict check: the result should appear where the payload was injected
  const originalPattern = originalValue;
  const resultPattern = originalValue + expectedResult;
  
  return cleanResponse.includes(resultPattern) && !cleanResponse.includes(payloadPattern);
}

function detectTemplateError(response: string): string | undefined {
  for (const signature of TEMPLATE_ERROR_SIGNATURES) {
    if (response.includes(signature)) {
      return signature;
    }
  }
  return undefined;
}

function detectContextAccess(response: string): string | undefined {
  for (const indicator of CONTEXT_INDICATORS) {
    if (response.toLowerCase().includes(indicator.toLowerCase())) {
      return indicator;
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
        detectionPhase: "math",
      },
    });
  });

  step("testMathematicalPayloads", async (state, context) => {
    const mathPayloads = getMathPayloadsForAggressivity(context.config.aggressivity);
    
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
          detectionPhase: "error",
        },
      });
    }

    const currentParam = state.testParams[state.currentParamIndex];
    const currentPayload = mathPayloads[state.currentPayloadIndex];
    
    if (currentParam === undefined || currentPayload === undefined) {
      return done({ state });
    }

    try {
      const testValue = currentParam.value + currentPayload.payload;
      const requestSpec = createRequestWithParameter(
        context,
        currentParam,
        testValue,
      );
      
      const { request, response } = await context.sdk.requests.send(requestSpec);
      
      if (response !== undefined) {
        const responseBody = response.getBody()?.toText();
        
        if (responseBody !== undefined) {
          if (detectMathematicalEvaluation(responseBody, currentPayload.expected, currentParam.value, currentPayload.payload)) {
            return done({
              findings: [
                {
                  name: `Server-Side Template Injection in parameter '${currentParam.name}'`,
                  description: `Parameter \`${currentParam.name}\` in ${currentParam.source} is vulnerable to Server-Side Template Injection. Mathematical expression evaluation was detected, indicating template engine processing of user input.\n\n**Payload used:**\n\`\`\`\n${currentPayload.payload}\n\`\`\`\n\n**Expected result:** \`${currentPayload.expected}\`\n**Template engines:** ${currentPayload.engines.join(", ")}\n**Detection method:** ${currentPayload.description}\n\n⚠️ **Critical Impact:** This vulnerability can lead to Remote Code Execution (RCE), full server compromise, and unauthorized access to sensitive data.`,
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
    const nextParamIndex = nextPayloadIndex >= mathPayloads.length 
      ? state.currentParamIndex + 1 
      : state.currentParamIndex;
    const resetPayloadIndex = nextPayloadIndex >= mathPayloads.length ? 0 : nextPayloadIndex;

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
    const errorPayloads = getErrorPayloadsForAggressivity(context.config.aggressivity);
    
    if (
      state.currentParamIndex >= state.testParams.length ||
      state.currentPayloadIndex >= errorPayloads.length
    ) {
      return continueWith({
        nextStep: "testContextPayloads",
        state: {
          ...state,
          currentParamIndex: 0,
          currentPayloadIndex: 0,
          detectionPhase: "context",
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
      const requestSpec = createRequestWithParameter(
        context,
        currentParam,
        testValue,
      );
      
      const { request, response } = await context.sdk.requests.send(requestSpec);
      
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
    const nextParamIndex = nextPayloadIndex >= errorPayloads.length 
      ? state.currentParamIndex + 1 
      : state.currentParamIndex;
    const resetPayloadIndex = nextPayloadIndex >= errorPayloads.length ? 0 : nextPayloadIndex;

    return continueWith({
      nextStep: "testErrorPayloads",
      state: {
        ...state,
        currentParamIndex: nextParamIndex,
        currentPayloadIndex: resetPayloadIndex,
      },
    });
  });

  step("testContextPayloads", async (state, context) => {
    const contextPayloads = getContextPayloadsForAggressivity(context.config.aggressivity);
    
    if (
      state.currentParamIndex >= state.testParams.length ||
      state.currentPayloadIndex >= contextPayloads.length
    ) {
      return done({ state });
    }

    const currentParam = state.testParams[state.currentParamIndex];
    const currentPayload = contextPayloads[state.currentPayloadIndex];
    
    if (currentParam === undefined || currentPayload === undefined) {
      return done({ state });
    }

    try {
      const testValue = currentParam.value + currentPayload.payload;
      const requestSpec = createRequestWithParameter(
        context,
        currentParam,
        testValue,
      );
      
      const { request, response } = await context.sdk.requests.send(requestSpec);
      
      if (response !== undefined) {
        const responseBody = response.getBody()?.toText();
        
        if (responseBody !== undefined) {
          const contextIndicator = detectContextAccess(responseBody);
          
          if (contextIndicator !== undefined) {
            return done({
              findings: [
                {
                  name: `Possible Server-Side Template Injection in parameter '${currentParam.name}'`,
                  description: `Parameter \`${currentParam.name}\` in ${currentParam.source} shows signs of template context access, which may indicate Server-Side Template Injection vulnerability.\n\n**Payload used:**\n\`\`\`\n${currentPayload.payload}\n\`\`\`\n\n**Context indicator detected:**\n\`\`\`\n${contextIndicator}\n\`\`\`\n\n**Detection method:** ${currentPayload.description}\n\n⚠️ **Medium Impact:** Template context access may indicate SSTI vulnerability. Manual verification is recommended to confirm exploitability.`,
                  severity: Severity.MEDIUM,
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
    const nextParamIndex = nextPayloadIndex >= contextPayloads.length 
      ? state.currentParamIndex + 1 
      : state.currentParamIndex;
    const resetPayloadIndex = nextPayloadIndex >= contextPayloads.length ? 0 : nextPayloadIndex;

    return continueWith({
      nextStep: "testContextPayloads",
      state: {
        ...state,
        currentParamIndex: nextParamIndex,
        currentPayloadIndex: resetPayloadIndex,
      },
    });
  });

  return {
    metadata: {
      id: "ssti",
      name: "Server-Side Template Injection",
      description: "Detects Server-Side Template Injection using mathematical expressions and error signatures",
      type: "active",
      tags: ["ssti", "injection", "rce", "template"],
      severities: [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
      aggressivity: {
        minRequests: 1,
        maxRequests: "Infinity",
      },
    },
    
    initState: () => ({
      testParams: [],
      currentParamIndex: 0,
      currentPayloadIndex: 0,
      detectionPhase: "math" as const,
    }),
    
    dedupeKey: (context) => {
      const query = context.request.getQuery();
      const paramKeys = query !== ""
        ? Array.from(new URLSearchParams(query).keys()).sort().join(",")
        : "";

      return (
        context.request.getMethod() +
        context.request.getHost() +
        context.request.getPort() +
        context.request.getPath() +
        paramKeys
      );
    },
    
    when: (target) => {
      const { request } = target;

      const queryString = request.getQuery();
      const hasQueryParams = queryString !== undefined && queryString.length > 0;
      const hasBody = request.getBody() !== undefined;

      return hasQueryParams || hasBody;
    },
  };
});
