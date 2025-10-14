import { continueWith, defineCheck, done, Severity } from "engine";

import { Tags } from "../../../types";
import {
  createRequestWithParameter,
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

const SQLITE_ERROR_PAYLOADS = ["'", '"', "\\"];

// SQLite-specific error messages from the source code (exact string matches)
const SQLITE_ERROR_SIGNATURES = [
  // SQLite-specific database errors
  "database disk image is malformed",
  "database schema has changed",
  "database corruption",

  // SQLite-specific constraint errors
  "FOREIGN KEY constraint failed",
  "CHECK constraint failed in",

  // SQLite-specific table/column/index errors
  "no such table:",
  "no such column:",
  "no such index:",
  "no such function:",
  "no such trigger:",
  "no such module:",
  "no such window:",
  "no such table column:",
  "no such view",
  "no such savepoint:",
  "no such rowid:",
  "no query solution",

  // SQLite-specific syntax errors
  "syntax error near",
  "syntax error after column name",

  // SQLite-specific union errors
  "SELECTs to the left and right of UNION do not have the same number of result columns",
  "all VALUES must have the same number of terms",

  // SQLite-specific function errors
  "no such function: randomblob",
];

// SQLite-specific error patterns (regex patterns for flexible matching)
const SQLITE_ERROR_REGEX_PATTERNS = [
  /near\s+".+":\s+syntax\s+error/i,
  /no\s+such\s+(table|column|index|function|trigger|module|window|view|savepoint|rowid):\s*"?[^"]*"?/i,
  /FOREIGN\s+KEY\s+constraint\s+failed/i,
  /CHECK\s+constraint\s+failed\s+in/i,
  /database\s+(disk\s+image\s+is\s+malformed|schema\s+has\s+changed|corruption)/i,
  /syntax\s+error\s+(near|after)/i,
  /SELECTs\s+to\s+the\s+left\s+and\s+right\s+of\s+UNION\s+do\s+not\s+have\s+the\s+same\s+number\s+of\s+result\s+columns/i,
  /all\s+VALUES\s+must\s+have\s+the\s+same\s+number\s+of\s+terms/i,
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

    if (state.currentPayloadIndex >= SQLITE_ERROR_PAYLOADS.length) {
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

    const currentPayload = SQLITE_ERROR_PAYLOADS[state.currentPayloadIndex];
    if (currentPayload === undefined) {
      return done({ state });
    }

    const testValue = currentParam.value + currentPayload;
    const testRequestSpec = createRequestWithParameter(
      context,
      currentParam,
      testValue,
    );
    const { request: testRequest, response: testResponse } =
      await context.sdk.requests.send(testRequestSpec);

    if (testResponse !== undefined) {
      const responseBody = testResponse.getBody()?.toText();
      if (responseBody !== undefined) {
        // Check exact string matches
        for (const signature of SQLITE_ERROR_SIGNATURES) {
          if (responseBody.includes(signature)) {
            return done({
              findings: [
                {
                  name:
                    "SQLite Error-Based SQL Injection in parameter '" +
                    currentParam.name +
                    "'",
                  description: `Parameter \`${currentParam.name}\` in ${currentParam.source} is vulnerable to SQLite error-based SQL injection. The application returned a SQLite error message, indicating that user input is not properly sanitized.\n\n**Payload used:**\n\`\`\`\n${testValue}\n\`\`\`\n\n**Error signature detected:**\n\`\`\`\n${signature}\n\`\`\``,
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

        // Check regex patterns
        for (const pattern of SQLITE_ERROR_REGEX_PATTERNS) {
          const match = responseBody.match(pattern);
          if (match) {
            return done({
              findings: [
                {
                  name:
                    "SQLite Error-Based SQL Injection in parameter '" +
                    currentParam.name +
                    "'",
                  description: `Parameter \`${currentParam.name}\` in ${currentParam.source} is vulnerable to SQLite error-based SQL injection. The application returned a SQLite error message, indicating that user input is not properly sanitized.\n\n**Payload used:**\n\`\`\`\n${testValue}\n\`\`\`\n\n**Error signature detected:**\n\`\`\`\n${match[0]}\n\`\`\``,
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
      id: "sqlite-error-based-sqli",
      name: "SQLite Error-Based SQL Injection",
      description:
        "Detects SQLite-specific error-based SQL injection vulnerabilities using actual SQLite error messages from the source code, including database errors, constraint violations, syntax errors, and system errors",
      type: "active",
      tags: [Tags.SQLI],
      severities: [Severity.CRITICAL],
      aggressivity: {
        minRequests: 1,
        maxRequests: SQLITE_ERROR_PAYLOADS.length,
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
