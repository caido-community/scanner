import type {
  Check,
  CheckMetadata,
  CheckOutput,
  CheckTask,
  StepTickResult,
} from "../types/check";
import type {
  CheckDefinitionV2,
  RegexCheckDefinition,
} from "../types/check-v2";
import type { Finding } from "../types/finding";
import type { RuntimeContext } from "../types/runner";

import { createCheckContext, type WrappedSdk } from "./check-context";

type CreateTaskContext = {
  runtimeContext: RuntimeContext;
  wrappedSdk: WrappedSdk;
  getInterrupted: () => boolean;
};

/**
 * Defines a single-execution check using the simpler V2 API.
 *
 * Use this when one `execute(ctx)` function is enough for the whole check. The
 * context gives you helpers like `send()`, `finding()`, `parameters()`, and
 * `target`, so simple checks can be written without defining explicit steps.
 */
export function defineCheckV2(config: CheckDefinitionV2): Check {
  const metadata: CheckMetadata = {
    id: config.id,
    name: config.name,
    description: config.description,
    type: config.type,
    tags: config.tags,
    severities: config.severities,
    aggressivity: config.aggressivity,
    dependsOn: config.dependsOn,
    minAggressivity: config.minAggressivity,
    skipIfFoundBy: config.skipIfFoundBy,
  };

  const create = (runtimeContext: RuntimeContext): CheckTask => {
    const findings: Finding[] = [];
    let hasRun = false;
    let output: CheckOutput = undefined;

    return {
      metadata,
      tick: async (): Promise<StepTickResult> => {
        if (hasRun) {
          return { status: "done", findings: [] };
        }
        hasRun = true;

        const taskContext = (
          runtimeContext as unknown as { __v2Context?: CreateTaskContext }
        ).__v2Context;
        if (!taskContext) {
          throw new Error(
            "V2 checks require RuntimeContext with __v2Context. " +
              "Ensure the engine is configured to support V2 checks.",
          );
        }

        const checkContext = createCheckContext({
          runtimeContext,
          wrappedSdk: taskContext.wrappedSdk,
          findings,
          getInterrupted: taskContext.getInterrupted,
        });

        const result = await config.execute(checkContext);
        if (result !== undefined) {
          output = result;
        }

        return { status: "done", findings };
      },
      getFindings: () => findings,
      getOutput: () => output,
      getTarget: () => runtimeContext.target,
      getCurrentStepName: () => (hasRun ? undefined : "execute"),
      getCurrentState: () => ({}),
    };
  };

  return {
    metadata,
    create,
    dedupeKey: config.dedupeKey,
    when: config.when,
  };
}

/**
 * Convenience helper for passive body-matching checks.
 *
 * Use this for checks that look for one or more regex matches in the response body
 * and convert the matches into a finding with `toFinding(...)`.
 */
export function defineRegexCheck(config: RegexCheckDefinition): Check {
  return defineCheckV2({
    id: config.id,
    name: config.name,
    description: config.description,
    type: "passive",
    tags: config.tags,
    severities: [config.severity],
    aggressivity: { minRequests: 0, maxRequests: 0 },
    dedupeKey: config.dedupeKey,
    when: config.when,

    execute(ctx): Promise<void> {
      const body = ctx.target.bodyText();
      if (body === undefined) return Promise.resolve();

      const allMatches = new Set<string>();

      for (const pattern of config.patterns) {
        const matches = body.matchAll(new RegExp(pattern, "g"));
        for (const match of matches) {
          if (match[0] !== undefined) {
            allMatches.add(match[0]);
          }
        }
      }

      if (allMatches.size === 0) return Promise.resolve();

      const { name, description } = config.toFinding(Array.from(allMatches));

      ctx.finding({
        name,
        severity: config.severity,
        description,
      });

      return Promise.resolve();
    },
  });
}
