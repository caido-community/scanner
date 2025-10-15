import { continueWith, defineCheck, done, Severity } from "engine";

import { Tags } from "../../../types";
import {
  createRequestWithParameter,
  extractParameters,
  findingBuilder,
  hasParameters,
  type Parameter,
} from "../../../utils";
import { keyStrategy } from "../../../utils/key";

type State = {
  testParams: Parameter[];
  currentPayloadIndex: number;
  currentParamIndex: number;
};

const SQLITE_ERROR_PAYLOADS = ["a'", 'a"', "a\\"];

// Finding constants
const FINDING_DESCRIPTION =
  "The application is vulnerable to SQLite error-based SQL injection. The application returned a SQLite error message, indicating that user input is not properly sanitized.";
const FINDING_IMPACT =
  "This vulnerability allows attackers to extract sensitive information from the database, including user credentials, personal data, and other confidential information. Attackers can also potentially manipulate database operations.";
const FINDING_RECOMMENDATION =
  "Use parameterized queries or prepared statements to prevent SQL injection. Never concatenate user input directly into SQL queries. Implement proper input validation and sanitization.";

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
const SQLITE_ERROR_REGEX_PATTERNS = [/near ".+?": syntax error/i];

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
            const finding = findingBuilder({
              name: "SQLite Error-Based SQL Injection",
              severity: Severity.CRITICAL,
              request: testRequest,
            })
              .withDescription(FINDING_DESCRIPTION)
              .withImpact(FINDING_IMPACT)
              .withRecommendation(FINDING_RECOMMENDATION)
              .withArtifacts("Payload and Error Details", [
                `Payload used: ${testValue}`,
                `Error signature detected: ${signature}`,
              ])
              .build();

            return done({
              findings: [finding],
              state,
            });
          }
        }

        // Check regex patterns
        for (const pattern of SQLITE_ERROR_REGEX_PATTERNS) {
          const match = responseBody.match(pattern);
          if (match) {
            const finding = findingBuilder({
              name: "SQLite Error-Based SQL Injection",
              severity: Severity.CRITICAL,
              request: testRequest,
            })
              .withDescription(FINDING_DESCRIPTION)
              .withImpact(FINDING_IMPACT)
              .withRecommendation(FINDING_RECOMMENDATION)
              .withArtifacts("Payload and Error Details", [
                `Payload used: ${testValue}`,
                `Error signature detected: ${match[0]}`,
              ])
              .build();

            return done({
              findings: [finding],
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
        "Detects SQLite-specific error-based SQL injection vulnerabilities",
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
