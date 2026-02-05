import type { SDK } from "caido:plugin";
import type { RequestSpec } from "caido:utils";

import type {
  AggressivityLimits,
  CheckContext,
  FindingInput,
  Parameter,
  SendErr,
  SendOk,
} from "../types/check-v2";
import type { Finding } from "../types/finding";
import type { Result } from "../types/result";
import { Result as ResultHelpers } from "../types/result";
import type { RuntimeContext, ScanAggressivity } from "../types/runner";

import { ScanRunnableInterruptedError } from "./errors";
import { extractParameters } from "./parameter";
import { createTargetAccessor } from "./target-accessor";

export type WrappedSdk = SDK;

export type CheckContextOptions = {
  runtimeContext: RuntimeContext;
  wrappedSdk: WrappedSdk;
  findings: Finding[];
  getInterrupted: () => boolean;
};

export function createCheckContext(options: CheckContextOptions): CheckContext {
  const { runtimeContext, wrappedSdk, findings, getInterrupted } = options;
  const targetAccessor = createTargetAccessor(runtimeContext.target);

  const send = async (spec: RequestSpec): Promise<Result<SendOk, SendErr>> => {
    try {
      const { request, response } = await wrappedSdk.requests.send(spec);
      return ResultHelpers.ok({ request, response });
    } catch (error) {
      if (error instanceof ScanRunnableInterruptedError) {
        throw error;
      }
      return ResultHelpers.err({
        error: error instanceof Error ? error.message : "Unknown error",
      });
    }
  };

  const finding = (input: FindingInput): void => {
    const request = input.request ?? runtimeContext.target.request;

    let description = input.description;

    if (input.impact !== undefined) {
      description += `\n\n## Impact\n${input.impact}`;
    }
    if (input.recommendation !== undefined) {
      description += `\n\n## Recommendation\n${input.recommendation}`;
    }
    if (input.artifacts !== undefined) {
      description += `\n\n## ${input.artifacts.title}\n${input.artifacts.items.map((i) => `- ${i}`).join("\n")}`;
    }

    const newFinding: Finding = {
      name: input.name,
      severity: input.severity,
      description,
      correlation: {
        requestID: request.getId(),
        locations: [],
      },
    };

    findings.push(newFinding);
  };

  const parameters = (opts?: { reflected?: boolean }): Parameter[] => {
    const responseBody = runtimeContext.target.response?.getBody()?.toText();
    return extractParameters(runtimeContext.target.request, {
      reflected: opts?.reflected,
      responseBody,
    });
  };

  const limit = <T>(items: T[], limits: AggressivityLimits): T[] => {
    const aggressivity = runtimeContext.config.aggressivity;
    const limitMap: Record<ScanAggressivity, number> = {
      low: limits.low,
      medium: limits.medium,
      high: limits.high,
    };
    return items.slice(0, limitMap[aggressivity]);
  };

  return {
    ...runtimeContext,
    sdk: wrappedSdk,
    target: targetAccessor,
    send,
    finding,
    parameters,
    limit,
    get interrupted() {
      return getInterrupted();
    },
  };
}
