import { defineCheckV2, generateRandomString, Result, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

type PhpInjectionProbe = {
  name: string;
  buildPayload: (input: { marker: string }) => string;
};

const TOKEN_PREFIX = "scanner-phpci-";
const LEFT_OPERAND = 1337;
const RIGHT_OPERAND = 7331;
const EXPECTED_RESULT = String(LEFT_OPERAND * RIGHT_OPERAND);

const PROBES: PhpInjectionProbe[] = [
  {
    name: "direct evaluation",
    buildPayload: ({ marker }) =>
      `print('${TOKEN_PREFIX}${marker}-' . (${LEFT_OPERAND}*${RIGHT_OPERAND}));`,
  },
  {
    name: "single-quote breakout",
    buildPayload: ({ marker }) =>
      `';print('${TOKEN_PREFIX}${marker}-' . (${LEFT_OPERAND}*${RIGHT_OPERAND}));#`,
  },
  {
    name: "double-quote breakout",
    buildPayload: ({ marker }) =>
      `";print('${TOKEN_PREFIX}${marker}-' . (${LEFT_OPERAND}*${RIGHT_OPERAND}));#`,
  },
  {
    name: "string concatenation breakout",
    buildPayload: ({ marker }) =>
      `'.print('${TOKEN_PREFIX}${marker}-' . (${LEFT_OPERAND}*${RIGHT_OPERAND})).'`,
  },
  {
    name: "parenthesis breakout",
    buildPayload: ({ marker }) =>
      `);print('${TOKEN_PREFIX}${marker}-' . (${LEFT_OPERAND}*${RIGHT_OPERAND}));#`,
  },
];

const PARAMETER_LIMITS = {
  low: 1,
  medium: 3,
  high: 5,
} as const;

const PROBE_LIMITS = {
  low: 2,
  medium: 4,
  high: PROBES.length,
} as const;

const createMarker = (usedMarkers: Set<string>): string => {
  let marker = generateRandomString(10).toLowerCase();
  let attempts = 0;

  while (usedMarkers.has(marker) && attempts < 5) {
    marker = generateRandomString(10).toLowerCase();
    attempts += 1;
  }

  usedMarkers.add(marker);
  return marker;
};

const buildExpectedToken = (marker: string): string => {
  return `${TOKEN_PREFIX}${marker}-${EXPECTED_RESULT}`;
};

export default defineCheckV2({
  id: "php-code-injection",
  name: "PHP code injection",
  description:
    "Detects PHP code injection by attempting to execute a PHP expression and verifying the output.",
  type: "active",
  tags: [Tags.INJECTION, Tags.RCE, Tags.INPUT_VALIDATION],
  severities: [Severity.CRITICAL],
  aggressivity: {
    minRequests: 1,
    maxRequests: "Infinity",
  },
  dedupeKey: keyStrategy()
    .withMethod()
    .withHost()
    .withPort()
    .withPath()
    .withQueryKeys()
    .build(),
  when: (target) => {
    if (target.response === undefined) {
      return false;
    }

    return (
      target.request.getQuery() !== "" || target.request.getBody() !== undefined
    );
  },
  async execute(ctx) {
    if (!ctx.target.hasParameters()) {
      return;
    }

    const parameters = ctx.parameters();
    if (parameters.length === 0) {
      return;
    }

    const limitedParameters = ctx.limit(parameters, PARAMETER_LIMITS);
    const limitedProbes = ctx.limit(PROBES, PROBE_LIMITS);

    const usedMarkers = new Set<string>();

    for (const parameter of limitedParameters) {
      for (const probe of limitedProbes) {
        const firstMarker = createMarker(usedMarkers);
        const firstExpected = buildExpectedToken(firstMarker);
        const firstPayload = probe.buildPayload({ marker: firstMarker });

        const firstResult = await ctx.send(parameter.inject(firstPayload));
        if (Result.isErr(firstResult)) {
          continue;
        }

        const firstBody = firstResult.value.response.getBody()?.toText();
        if (firstBody === undefined || !firstBody.includes(firstExpected)) {
          continue;
        }

        const secondMarker = createMarker(usedMarkers);
        const secondExpected = buildExpectedToken(secondMarker);
        const secondPayload = probe.buildPayload({ marker: secondMarker });

        const secondResult = await ctx.send(parameter.inject(secondPayload));
        if (Result.isErr(secondResult)) {
          continue;
        }

        const secondBody = secondResult.value.response.getBody()?.toText();
        if (secondBody === undefined || !secondBody.includes(secondExpected)) {
          continue;
        }

        ctx.finding({
          name: `PHP code injection in parameter '${parameter.name}'`,
          severity: Severity.CRITICAL,
          description: `Parameter \`${parameter.name}\` from ${parameter.source} appears to be evaluated as PHP code. The application returned output consistent with execution of an injected PHP expression.`,
          impact:
            "An attacker could execute arbitrary PHP code on the server, potentially leading to full remote code execution, data exfiltration, and server compromise.",
          recommendation:
            "Avoid evaluating user input as PHP code. Remove uses of eval/assert with untrusted input, enforce strict allowlists, and apply context-appropriate encoding/escaping.",
          artifacts: {
            title: "Detection details",
            items: [
              `Probe: ${probe.name}`,
              `Attempt 1 payload: ${firstPayload}`,
              `Attempt 1 expected token: ${firstExpected}`,
              `Attempt 2 payload: ${secondPayload}`,
              `Attempt 2 expected token: ${secondExpected}`,
            ],
          },
          request: secondResult.value.request,
        });
        return;
      }
    }
  },
});
