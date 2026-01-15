import {
  continueWith,
  defineCheck,
  done,
  ScanAggressivity,
  Severity,
} from "engine";

import { Tags } from "../../types";
import {
  createRequestWithParameter,
  extractParameters,
  findingBuilder,
  hasParameters,
  type Parameter,
} from "../../utils";
import { keyStrategy } from "../../utils/key";

type TransformCheck = {
  name: string;
  probe: string;
  expectedValues: string[];
};

type State = {
  testParams: Parameter[];
  currentParamIndex: number;
  currentCheckIndex: number;
  confirmationAttempts: number;
  checks: TransformCheck[];
};

function generateRandomString(length: number): string {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function generateArithmeticExpression(): { probe: string; expected: string } {
  const x = 99 + Math.floor(Math.random() * 1337);
  const y = 99 + Math.floor(Math.random() * 1337);
  const probe = `${x}*${y}`;
  const expected = String(x * y);
  return { probe, expected };
}

function getChecksForAggressivity(
  aggressivity: ScanAggressivity,
): TransformCheck[] {
  const leftAnchor = generateRandomString(6);
  const rightAnchor = generateRandomString(6);
  const arithmetic = generateArithmeticExpression();

  const allChecks: TransformCheck[] = [
    {
      name: "unicode normalization",
      probe: `${leftAnchor}\u212a${rightAnchor}`,
      expectedValues: [`${leftAnchor}K${rightAnchor}`],
    },
    {
      name: "url decoding error",
      probe: `${leftAnchor}\u0391${rightAnchor}`,
      expectedValues: [`${leftAnchor}N\u0011${rightAnchor}`],
    },
    {
      name: "unicode byte truncation",
      probe: `${leftAnchor}\uCF7B${rightAnchor}`,
      expectedValues: [`${leftAnchor}{${rightAnchor}`],
    },
    {
      name: "unicode case conversion",
      probe: `${leftAnchor}\u0131${rightAnchor}`,
      expectedValues: [`${leftAnchor}I${rightAnchor}`],
    },
    {
      name: "unicode combining diacritic",
      probe: `\u0338${rightAnchor}`,
      expectedValues: [`\u226F${rightAnchor}`],
    },
    {
      name: "quote consumption",
      probe: `${leftAnchor}''${rightAnchor}`,
      expectedValues: [`${leftAnchor}'${rightAnchor}`],
    },
    {
      name: "arithmetic evaluation",
      probe: arithmetic.probe,
      expectedValues: [arithmetic.expected],
    },
    {
      name: "expression evaluation",
      probe: `\${${arithmetic.probe}}`,
      expectedValues: [arithmetic.expected],
    },
    {
      name: "template evaluation",
      probe: `@(${arithmetic.probe})`,
      expectedValues: [arithmetic.expected],
    },
    {
      name: "EL evaluation",
      probe: `%{${arithmetic.probe}}`,
      expectedValues: [arithmetic.expected],
    },
  ];

  switch (aggressivity) {
    case ScanAggressivity.LOW:
      return allChecks.slice(0, 3);
    case ScanAggressivity.MEDIUM:
      return allChecks.slice(0, 6);
    case ScanAggressivity.HIGH:
      return allChecks;
    default:
      return allChecks.slice(0, 3);
  }
}

export default defineCheck<State>(({ step }) => {
  step("findParameters", (state, context) => {
    const testParams = extractParameters(context);

    if (testParams.length === 0) {
      return done({ state });
    }

    const checks = getChecksForAggressivity(context.config.aggressivity);

    return continueWith({
      nextStep: "testTransforms",
      state: {
        ...state,
        testParams,
        checks,
        currentParamIndex: 0,
        currentCheckIndex: 0,
        confirmationAttempts: 0,
      },
    });
  });

  step("testTransforms", async (state, context) => {
    const confirmCount = 2;

    if (
      state.currentParamIndex >= state.testParams.length ||
      state.currentCheckIndex >= state.checks.length
    ) {
      return done({ state });
    }

    const currentParam = state.testParams[state.currentParamIndex];
    const currentCheck = state.checks[state.currentCheckIndex];

    if (currentParam === undefined || currentCheck === undefined) {
      return done({ state });
    }

    const initialResponse = context.target.response;
    const initialResponseBody = initialResponse?.getBody()?.toText();

    if (initialResponseBody === undefined) {
      return continueWith({
        nextStep: "testTransforms",
        state: {
          ...state,
          currentCheckIndex: state.currentCheckIndex + 1,
          confirmationAttempts: 0,
        },
      });
    }

    const skipDueToInitialPresence = currentCheck.expectedValues.some(
      (expected) => initialResponseBody.includes(expected),
    );

    if (skipDueToInitialPresence) {
      return continueWith({
        nextStep: "testTransforms",
        state: {
          ...state,
          currentCheckIndex: state.currentCheckIndex + 1,
          confirmationAttempts: 0,
        },
      });
    }

    try {
      const requestSpec = createRequestWithParameter(
        context,
        currentParam,
        currentCheck.probe,
      );

      const { request, response } =
        await context.sdk.requests.send(requestSpec);

      if (response !== undefined) {
        const responseBody = response.getBody()?.toText();

        if (responseBody !== undefined) {
          const matched = currentCheck.expectedValues.some(
            (expected) =>
              responseBody.includes(expected) &&
              !initialResponseBody.includes(expected),
          );

          if (matched) {
            const newConfirmationAttempts = state.confirmationAttempts + 1;

            if (newConfirmationAttempts >= confirmCount) {
              const finding = findingBuilder({
                name: `Suspicious input transformation: ${currentCheck.name}`,
                severity: Severity.HIGH,
                request,
              })
                .withDescription(
                  `The application transforms user input in parameter ${currentParam.name} in an unexpected way that may indicate a security vulnerability.`,
                )
                .withImpact(
                  "Input transformation vulnerabilities can lead to code injection, authentication bypass, or validation bypass attacks.",
                )
                .withRecommendation(
                  "Implement strict input validation and avoid dynamic evaluation of user input. Review the application's input processing logic.",
                )
                .withArtifacts("Detection Details", [
                  `Transformation Type: ${currentCheck.name}`,
                  `Probe Sent: ${currentCheck.probe}`,
                  `Expected Values: ${currentCheck.expectedValues.join(", ")}`,
                  `Confirmed: Yes (${confirmCount} consecutive detections)`,
                ])
                .build();

              const nextCheckIndex = state.currentCheckIndex + 1;
              const nextParamIndex =
                nextCheckIndex >= state.checks.length
                  ? state.currentParamIndex + 1
                  : state.currentParamIndex;
              const resetCheckIndex =
                nextCheckIndex >= state.checks.length ? 0 : nextCheckIndex;

              return continueWith({
                findings: [finding],
                nextStep: "testTransforms",
                state: {
                  ...state,
                  currentParamIndex: nextParamIndex,
                  currentCheckIndex: resetCheckIndex,
                  confirmationAttempts: 0,
                },
              });
            }

            return continueWith({
              nextStep: "testTransforms",
              state: {
                ...state,
                confirmationAttempts: newConfirmationAttempts,
              },
            });
          }

          if (state.confirmationAttempts > 0) {
            return continueWith({
              nextStep: "testTransforms",
              state: {
                ...state,
                currentCheckIndex: state.currentCheckIndex + 1,
                confirmationAttempts: 0,
              },
            });
          }
        }
      }
    } catch {
      // ignore
    }

    const nextCheckIndex = state.currentCheckIndex + 1;
    const nextParamIndex =
      nextCheckIndex >= state.checks.length
        ? state.currentParamIndex + 1
        : state.currentParamIndex;
    const resetCheckIndex =
      nextCheckIndex >= state.checks.length ? 0 : nextCheckIndex;

    return continueWith({
      nextStep: "testTransforms",
      state: {
        ...state,
        currentParamIndex: nextParamIndex,
        currentCheckIndex: resetCheckIndex,
        confirmationAttempts: 0,
      },
    });
  });

  return {
    metadata: {
      id: "suspect-transform",
      name: "Suspicious Input Transformation",
      description:
        "Detects suspicious input transformations including unicode normalization, expression evaluation, and other transformations that may indicate vulnerabilities",
      type: "active",
      tags: [Tags.INJECTION],
      severities: [Severity.HIGH],
      aggressivity: {
        minRequests: 1,
        maxRequests: "Infinity",
      },
    },
    initState: () => ({
      testParams: [],
      currentParamIndex: 0,
      currentCheckIndex: 0,
      confirmationAttempts: 0,
      checks: [],
    }),
    dedupeKey: keyStrategy()
      .withMethod()
      .withHost()
      .withPort()
      .withPath()
      .withQueryKeys()
      .build(),
    when: (target) => hasParameters(target),
  };
});
