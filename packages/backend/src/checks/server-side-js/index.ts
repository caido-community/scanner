import {
  continueWith,
  defineCheck,
  done,
  Severity,
  type StepResult,
} from "engine";

import { Tags } from "../../types";
import {
  createRequestWithParameter,
  extractParameters,
  hasParameters,
  type Parameter,
} from "../../utils";
import { keyStrategy } from "../../utils/key";

type State = {
  testParams: Parameter[];
  currentParamIndex: number;
  currentPayloadIndex: number;
};

type PayloadConfig = {
  description: string;
  build: (marker: string) => string;
};

const MARKER_PREFIX = "__ssjs_probe__";

const PAYLOADS: PayloadConfig[] = [
  {
    description: "Single quote termination with Error throw",
    build: (marker) => `';throw new Error("${marker}")//`,
  },
  {
    description: "Double quote termination with Error throw",
    build: (marker) => `";throw new Error('${marker}')//`,
  },
  {
    description: "Parenthesis termination with Error throw",
    build: (marker) => `);throw new Error("${marker}");//`,
  },
];

const generateMarker = () =>
  `${MARKER_PREFIX}${Math.random().toString(36).slice(2, 10)}`;

const advanceState = (state: State): StepResult<State>["state"] => {
  let nextPayloadIndex = state.currentPayloadIndex + 1;
  let nextParamIndex = state.currentParamIndex;

  if (nextPayloadIndex >= PAYLOADS.length) {
    nextPayloadIndex = 0;
    nextParamIndex += 1;
  }

  return {
    ...state,
    currentParamIndex: nextParamIndex,
    currentPayloadIndex: nextPayloadIndex,
  };
};

export default defineCheck<State>(({ step }) => {
  step("findParameters", (state, context) => {
    const params = extractParameters(context);

    if (params.length === 0) {
      return done({ state });
    }

    return continueWith({
      nextStep: "testPayloads",
      state: {
        ...state,
        testParams: params,
        currentParamIndex: 0,
        currentPayloadIndex: 0,
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

    const parameter = state.testParams[state.currentParamIndex];
    const payloadConfig = PAYLOADS[state.currentPayloadIndex];

    const marker = generateMarker();
    const requestSpec = createRequestWithParameter(
      context,
      parameter,
      payloadConfig.build(marker),
    );

    const result = await context.sdk.requests.send(requestSpec);
    const responseBody = result.response?.getBody()?.toText() ?? "";

    if (responseBody.includes(marker)) {
      const description = [
        `The parameter \`${parameter.name}\` appears to execute injected JavaScript on the server side.`,
        "",
        `The payload used attempted to throw a controlled error with the marker \`${marker}\`. The server responded with the same marker, indicating that the JavaScript payload was executed.`,
        "",
        "**Payload description:**",
        payloadConfig.description,
      ].join("\n");

      return done({
        state,
        findings: [
          {
            name: `Server-side JavaScript code injection in parameter '${parameter.name}'`,
            description,
            severity: Severity.CRITICAL,
            correlation: {
              requestID: result.request.getId(),
              locations: [],
            },
          },
        ],
      });
    }

    const nextState = advanceState(state);

    if (nextState.currentParamIndex >= nextState.testParams.length) {
      return done({ state: nextState });
    }

    return continueWith({
      nextStep: "testPayloads",
      state: nextState,
    });
  });

  return {
    metadata: {
      id: "server-side-js-code-injection",
      name: "Server-side JavaScript code injection",
      description:
        "Attempts to trigger server-side JavaScript execution by inducing controlled errors",
      type: "active",
      tags: [Tags.INJECTION, Tags.RCE, Tags.INPUT_VALIDATION],
      severities: [Severity.CRITICAL],
      aggressivity: { minRequests: 0, maxRequests: "Infinity" },
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
      .build(),
    when: (target) => hasParameters(target),
  };
});
