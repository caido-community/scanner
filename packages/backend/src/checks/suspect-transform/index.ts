import { defineCheckV2, generateRandomString, Result, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

type TransformProbe = {
  name: string;
  probe: string;
  expectedValues: string[];
};

function generateArithmeticExpression(): { probe: string; expected: string } {
  const x = 99 + Math.floor(Math.random() * 1337);
  const y = 99 + Math.floor(Math.random() * 1337);
  const probe = `${x}*${y}`;
  const expected = String(x * y);
  return { probe, expected };
}

function buildProbes(): TransformProbe[] {
  const leftAnchor = generateRandomString(6);
  const rightAnchor = generateRandomString(6);
  const arithmetic = generateArithmeticExpression();

  return [
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
}

const CONFIRMATION_COUNT = 2;

export default defineCheckV2({
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
  dedupeKey: keyStrategy()
    .withMethod()
    .withHost()
    .withPort()
    .withPath()
    .withQueryKeys()
    .build(),
  when: (target) =>
    target.request.getQuery() !== "" || target.request.getBody() !== undefined,

  async execute(ctx) {
    if (!ctx.target.hasParameters()) return;

    const params = ctx.parameters();
    if (params.length === 0) return;

    const initialResponseBody = ctx.target.bodyText();
    if (initialResponseBody === undefined) return;

    const allProbes = buildProbes();
    const probes = ctx.limit(allProbes, { low: 3, medium: 6, high: 10 });

    for (const param of params) {
      for (const probe of probes) {
        const skipDueToInitialPresence = probe.expectedValues.some((expected) =>
          initialResponseBody.includes(expected),
        );
        if (skipDueToInitialPresence) continue;

        let confirmations = 0;

        for (let attempt = 0; attempt < CONFIRMATION_COUNT; attempt++) {
          const spec = param.inject(probe.probe);
          const result = await ctx.send(spec);
          if (Result.isErr(result)) break;

          const responseBody = result.value.response.getBody()?.toText();
          if (responseBody === undefined) break;

          const matched = probe.expectedValues.some(
            (expected) =>
              responseBody.includes(expected) &&
              !initialResponseBody.includes(expected),
          );

          if (!matched) break;

          confirmations++;

          if (confirmations >= CONFIRMATION_COUNT) {
            ctx.finding({
              name: `Suspicious input transformation: ${probe.name}`,
              severity: Severity.HIGH,
              description: `The application transforms user input in parameter ${param.name} in an unexpected way that may indicate a security vulnerability.`,
              impact:
                "Input transformation vulnerabilities can lead to code injection, authentication bypass, or validation bypass attacks.",
              recommendation:
                "Implement strict input validation and avoid dynamic evaluation of user input. Review the application's input processing logic.",
              artifacts: {
                title: "Detection Details",
                items: [
                  `Transformation Type: ${probe.name}`,
                  `Probe Sent: ${probe.probe}`,
                  `Expected Values: ${probe.expectedValues.join(", ")}`,
                  `Confirmed: Yes (${CONFIRMATION_COUNT} consecutive detections)`,
                ],
              },
              request: result.value.request,
            });
          }
        }
      }
    }
  },
});
