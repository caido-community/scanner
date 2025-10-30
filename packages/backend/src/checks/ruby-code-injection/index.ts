import { defineCheck, done, Severity } from "engine";

import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

const RUBY_EXPRESSION_PATTERN =
  /(?:puts|print|eval|exec|system|IO\.popen|`|%x\{|Kernel\.exec|Kernel\.system)/i;

const RUBY_ERROR_PATTERN =
  /(SyntaxError|NameError|NoMethodError|LoadError|RuntimeError):/i;

const buildDescription = (evidence: string): string => {
  return [
    "The response suggests that Ruby code was executed or evaluated with user-controlled input.",
    "",
    `Evidence snippet: \`${evidence}\``,
    "",
    "Ruby code injection can lead to remote code execution. Ensure input is not passed to Ruby evaluation primitives such as `eval`, `instance_eval`, or backticks.",
  ].join("\n");
};

export default defineCheck<Record<never, never>>(({ step }) => {
  step("detectRubyEval", (state, context) => {
    const { response } = context.target;

    if (response === undefined) {
      return done({ state });
    }

    const body = response.getBody()?.toText();
    if (body === undefined || body.length === 0) {
      return done({ state });
    }

    const trimmedBody = body.trim().slice(0, 2000);

    if (
      RUBY_EXPRESSION_PATTERN.test(trimmedBody) ||
      RUBY_ERROR_PATTERN.test(trimmedBody)
    ) {
      const evidence = trimmedBody.split("\n").slice(0, 3).join("\n");
      return done({
        state,
        findings: [
          {
            name: "Potential Ruby code injection",
            description: buildDescription(evidence),
            severity: Severity.HIGH,
            correlation: {
              requestID: context.target.request.getId(),
              locations: [],
            },
          },
        ],
      });
    }

    return done({ state });
  });

  return {
    metadata: {
      id: "ruby-code-injection",
      name: "Ruby code injection",
      description:
        "Detects responses indicating that Ruby code may have been evaluated from user input.",
      type: "passive",
      tags: [Tags.INJECTION, Tags.RCE],
      severities: [Severity.HIGH],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPath().build(),
    when: (target) => target.response !== undefined,
  };
});
