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
  payloads: (sleepSeconds: number) => string[];
};

const DATABASES: DatabasePayload[] = [
  {
    name: "MySQL",
    payloads: (sleepSeconds) => [
      ` AND SLEEP(${sleepSeconds})`,
      `AND IF(1=1,SLEEP(${sleepSeconds}),0)`,
      `XOR(IF(1=1,SLEEP(${sleepSeconds}),0))`,
    ],
  },
  {
    name: "PostgreSQL",
    payloads: (sleepSeconds) => [
      ` AND pg_sleep(${sleepSeconds})`,
      `'; SELECT pg_sleep(${sleepSeconds}) --`,
      `" AND pg_sleep(${sleepSeconds}) --`,
    ],
  },
];

const BASE_SLEEP_SECONDS = 10;
const CONFIRM_SLEEP_SECONDS = 15;
const DELAY_OFFSET_RATIO = 0.1;

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

    const allPayloads = DATABASES.flatMap((db) => {
      const basePayloads = db.payloads(BASE_SLEEP_SECONDS);
      const confirmPayloads = db.payloads(CONFIRM_SLEEP_SECONDS);

      return basePayloads.map((payload, index) => ({
        payload,
        confirmPayload: confirmPayloads[index],
        dbName: db.name,
      }));
    });

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

    const {
      payload: currentPayload,
      confirmPayload,
      dbName,
    } = currentPayloadData;
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
      const observedDelay = roundtripTime - state.baselineTime;
      const expectedDelay = BASE_SLEEP_SECONDS * 1000;
      const delayDelta = Math.abs(observedDelay - expectedDelay);
      const delayDetected = delayDelta <= expectedDelay * DELAY_OFFSET_RATIO;

      if (delayDetected && confirmPayload !== undefined) {
        const confirmValue = currentParam.value + confirmPayload;
        const confirmRequestSpec = createRequestWithParameter(
          context,
          currentParam,
          confirmValue,
        );

        let confirmResponse;
        try {
          const result = await context.sdk.requests.send(confirmRequestSpec);
          confirmResponse = result.response;
        } catch {
          return continueWith({
            nextStep: "testPayloads",
            state: {
              ...state,
              currentPayloadIndex: state.currentPayloadIndex + 1,
            },
          });
        }

        if (confirmResponse === undefined) {
          return continueWith({
            nextStep: "testPayloads",
            state: {
              ...state,
              currentPayloadIndex: state.currentPayloadIndex + 1,
            },
          });
        }

        const confirmRoundtripTime = confirmResponse.getRoundtripTime();
        const confirmObservedDelay = confirmRoundtripTime - state.baselineTime;
        const confirmExpectedDelay = CONFIRM_SLEEP_SECONDS * 1000;
        const confirmDelayDelta = Math.abs(
          confirmObservedDelay - confirmExpectedDelay,
        );
        const confirmDelayDetected =
          confirmDelayDelta <= confirmExpectedDelay * DELAY_OFFSET_RATIO;

        if (!confirmDelayDetected) {
          return continueWith({
            nextStep: "testPayloads",
            state: {
              ...state,
              currentPayloadIndex: state.currentPayloadIndex + 1,
            },
          });
        }

        return done({
          findings: [
            {
              name: `Time-Based SQL Injection in parameter '${currentParam.name}' (${dbName})`,
              description: `Parameter \`${currentParam.name}\` in ${currentParam.source} is vulnerable to time-based SQL injection. The application response was delayed by approximately ${(roundtripTime / 1000).toFixed(2)} seconds, indicating that a time-based injection payload was executed.\n\n**Database detected:** ${dbName}\n\n**Payload used:**\n\`\`\`\n${testValue}\n\`\`\`\n\n**Confirmation payload:**\n\`\`\`\n${confirmValue}\n\`\`\`\n\n**Baseline response time:** ${state.baselineTime.toFixed(2)}ms\n**Observed response time:** ${roundtripTime.toFixed(2)}ms\n**Detected delay:** ${observedDelay.toFixed(2)}ms\n\n**Confirmed response time:** ${confirmRoundtripTime.toFixed(2)}ms\n**Confirmed delay:** ${confirmObservedDelay.toFixed(2)}ms\n\n**Tested databases:** MySQL, PostgreSQL`,
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
      severities: [Severity.CRITICAL],
      aggressivity: {
        minRequests: 1,
        maxRequests:
          DATABASES.flatMap((db) => db.payloads(BASE_SLEEP_SECONDS)).length + 2,
      },
      skipIfFoundBy: ["mysql-error-based-sqli"],
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
