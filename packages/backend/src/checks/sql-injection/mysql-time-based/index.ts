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
  baselineTime: number;
};

type DatabasePayload = {
  name: string;
  payloads: string[];
};

const DATABASES: DatabasePayload[] = [
  {
    name: "MySQL",
    payloads: [
      ` AND SLEEP(10)`,
      `AND IF(1=1,SLEEP(10),0)`,
      `XOR(IF(1=1,SLEEP(10),0))`,
    ],
  },
  {
    name: "PostgreSQL",
    payloads: [
      ` AND pg_sleep(10)`,
      `'; SELECT pg_sleep(10) --`,
      `" AND pg_sleep(10) --`,
    ],
  },
];

const DELAY_THRESHOLD_MS = 8000;

export default defineCheck<State>(({ step }) => {
  step("measureBaseline", async (state, context) => {
    const testParams = extractParameters(context);

    if (testParams.length === 0) {
      return done({ state });
    }

    const baselineRequestSpec = context.target.request.toSpec();
    let baselineTime = 0;

    try {
      const { response: baselineResponse } =
        await context.sdk.requests.send(baselineRequestSpec);
      baselineTime = baselineResponse?.getRoundtripTime() ?? 0;
    } catch {
      return done({ state });
    }

    return continueWith({
      nextStep: "testPayloads",
      state: {
        ...state,
        testParams,
        currentPayloadIndex: 0,
        currentParamIndex: 0,
        baselineTime,
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

    const allPayloads = DATABASES.flatMap((db) =>
      db.payloads.map((p) => ({ payload: p, dbName: db.name })),
    );

    if (state.currentPayloadIndex >= allPayloads.length) {
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

    const currentPayloadData = allPayloads[state.currentPayloadIndex];
    if (currentPayloadData === undefined) {
      return done({ state });
    }

    const { payload: currentPayload, dbName } = currentPayloadData;
    const testValue = currentParam.value + currentPayload;
    const testRequestSpec = createRequestWithParameter(
      context,
      currentParam,
      testValue,
    );

    let testRequest;
    let testResponse;
    try {
      const result = await context.sdk.requests.send(testRequestSpec);
      testRequest = result.request;
      testResponse = result.response;
    } catch {
      return continueWith({
        nextStep: "testPayloads",
        state: {
          ...state,
          currentPayloadIndex: state.currentPayloadIndex + 1,
        },
      });
    }

    if (testResponse !== undefined) {
      const roundtripTime = testResponse.getRoundtripTime();
      const delayDetected = roundtripTime - state.baselineTime > DELAY_THRESHOLD_MS;

      if (delayDetected) {
        return done({
          findings: [
            {
              name:
                `Time-Based SQL Injection in parameter '${currentParam.name}' (${dbName})`,
              description: `Parameter \`${currentParam.name}\` in ${currentParam.source} is vulnerable to time-based SQL injection. The application response was delayed by approximately ${(roundtripTime / 1000).toFixed(2)} seconds, indicating that a time-based injection payload was executed.\n\n**Database detected:** ${dbName}\n\n**Payload used:**\n\`\`\`\n${testValue}\n\`\`\`\n\n**Baseline response time:** ${state.baselineTime.toFixed(2)}ms\n**Observed response time:** ${roundtripTime.toFixed(2)}ms\n**Detected delay:** ${(roundtripTime - state.baselineTime).toFixed(2)}ms\n\n**Tested databases:** MySQL, PostgreSQL`,
              severity: Severity.HIGH,
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
      id: "time-based-sqli",
      name: "Time-Based SQL Injection",
      description:
        "Detects time-based SQL injection vulnerabilities in MySQL and PostgreSQL databases by measuring response delays",
      type: "active",
      tags: [Tags.SQLI],
      severities: [Severity.HIGH],
      aggressivity: {
        minRequests: 1,
        maxRequests: DATABASES.flatMap((db) => db.payloads).length + 1,
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
      baselineTime: 0,
    }),
    when: (target) => {
      return hasParameters(target);
    },
  };
});
