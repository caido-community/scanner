import { continueWith, defineCheck, done, Severity } from "engine";

import { Tags } from "../../../types";
import {
  extractParameters,
  hasParameters,
  type Parameter,
} from "../../../utils";
import { keyStrategy } from "../../../utils/key";

type State = {
  testParams: Parameter[];
  currentPayloadIndex: number;
  currentParamIndex: number;
};

const MYSQL_ERROR_PAYLOADS = ["'", '"', "\\", "' OR SLEEP()=SLEEP() --"];

const MYSQL_ERROR_SIGNATURES = [
  "You have an error in your SQL syntax",
  "mysql_fetch_array()",
  "mysql_fetch_assoc()",
  "mysql_fetch_row()",
  "mysql_num_rows()",
  "MySQL server version",
  "supplied argument is not a valid MySQL",
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

    if (state.currentPayloadIndex >= MYSQL_ERROR_PAYLOADS.length) {
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

    const currentPayload = MYSQL_ERROR_PAYLOADS[state.currentPayloadIndex];
    if (currentPayload === undefined) {
      return done({ state });
    }

    const testValue = currentParam.value + currentPayload;
    const testRequestSpec = currentParam.inject(testValue);
    const { request: testRequest, response: testResponse } =
      await context.sdk.requests.send(testRequestSpec);

    if (testResponse !== undefined) {
      const responseBody = testResponse.getBody()?.toText();
      if (responseBody !== undefined) {
        for (const signature of MYSQL_ERROR_SIGNATURES) {
          if (responseBody.includes(signature)) {
            return done({
              findings: [
                {
                  name:
                    "MySQL Error-Based SQL Injection in parameter '" +
                    currentParam.name +
                    "'",
                  description: `Parameter \`${currentParam.name}\` in ${currentParam.source} is vulnerable to MySQL error-based SQL injection. The application returned a MySQL error message, indicating that user input is not properly sanitized.\n\n**Payload used:**\n\`\`\`\n${testValue}\n\`\`\`\n\n**Error signature detected:**\n\`\`\`\n${signature}\n\`\`\``,
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
      id: "mysql-error-based-sqli",
      name: "MySQL Error-Based SQL Injection",
      description:
        "Detects MySQL-specific error-based SQL injection vulnerabilities by triggering database errors",
      type: "active",
      tags: [Tags.SQLI],
      severities: [Severity.CRITICAL],
      aggressivity: {
        minRequests: 1,
        maxRequests: MYSQL_ERROR_PAYLOADS.length,
      },
    },
    dedupeKey: keyStrategy()
      .withMethod()
      .withHost()
      .withPort()
      .withPath()
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
