import { type SDK } from "caido:plugin";
import { type Request, type Response } from "caido:utils";

import { createRegistry } from "../core/registry";
import { type Check, type CheckOutput } from "../types/check";
import { type Finding } from "../types/finding";
import { ScanAggressivity, type ScanConfig } from "../types/runner";

import { createMockRequest } from "./mocks/request";
import { createMockResponse } from "./mocks/response";
import { createTestSdk } from "./mocks/sdk";
import {
  type MockRequestData,
  type MockRequestResponsePair,
  type MockResponseDataInput,
  type SendHandler,
} from "./mocks/types";

type TestCheckOptions = {
  config?: Partial<ScanConfig>;
  sendHandler?: SendHandler;
};

type TestCheckResult = {
  findings: Finding[];
  output: CheckOutput;
};

type MockTargetOptions = {
  request: MockRequestData;
  response?: MockResponseDataInput;
};

export function mockTarget(options: MockTargetOptions): {
  request: Request;
  response?: Response;
} {
  const request = createMockRequest(options.request);
  const response =
    options.response !== undefined
      ? createMockResponse(options.response)
      : undefined;
  return { request, response };
}

const createFullConfig = (options?: TestCheckOptions): ScanConfig => ({
  aggressivity: ScanAggressivity.MEDIUM,
  inScopeOnly: false,
  concurrentChecks: 1,
  concurrentRequests: 1,
  concurrentTargets: 1,
  requestsDelayMs: 0,
  scanTimeout: 30000,
  checkTimeout: 10000,
  severities: ["info", "low", "medium", "high", "critical"],
  ...options?.config,
});

const createRequestsMap = (
  requestResponsePairs: { request: Request; response?: Response }[],
): Record<string, MockRequestResponsePair> => {
  const requests: Record<string, MockRequestResponsePair> = {};

  for (const pair of requestResponsePairs) {
    requests[pair.request.getId()] = {
      request: {
        id: pair.request.getId(),
        host: pair.request.getHost(),
        port: pair.request.getPort(),
        tls: pair.request.getTls(),
        method: pair.request.getMethod(),
        path: pair.request.getPath(),
        query: pair.request.getQuery(),
        headers: pair.request.getHeaders(),
        body: pair.request.getBody()?.toText(),
      },
      response: pair.response
        ? {
            id: pair.response.getId(),
            code: pair.response.getCode(),
            headers: pair.response.getHeaders(),
            body: pair.response.getBody()?.toText(),
            roundtripTime: pair.response.getRoundtripTime(),
            createdAt: pair.response.getCreatedAt(),
          }
        : undefined,
    };
  }

  return requests;
};

export async function testCheck(
  checkDefinition: Check,
  target: { request: Request; response?: Response },
  options?: TestCheckOptions,
): Promise<TestCheckResult> {
  const fullConfig = createFullConfig(options);
  const requests = createRequestsMap([target]);

  const testSdk = createTestSdk({
    requests,
    sendHandler: options?.sendHandler,
  });

  const registry = createRegistry();
  registry.register(checkDefinition);

  const runnable = registry.create(
    testSdk as unknown as SDK<object, object>,
    fullConfig,
  );

  const requestIDs = [target.request.getId()];
  await runnable.run(requestIDs);

  const history = runnable.getExecutionHistory();
  const record = history[0];

  if (!record) {
    return { findings: [], output: undefined };
  }

  const findings = record.steps.flatMap((step) => step.findings);
  const output = record.status === "completed" ? record.finalOutput : undefined;

  return { findings, output };
}

export async function testChecks(
  checkDefinitions: Check[],
  targets: { request: Request; response?: Response }[],
  options?: TestCheckOptions,
): Promise<TestCheckResult[]> {
  const fullConfig = createFullConfig(options);
  const requests = createRequestsMap(targets);

  const testSdk = createTestSdk({
    requests,
    sendHandler: options?.sendHandler,
  });

  const registry = createRegistry();
  for (const checkDefinition of checkDefinitions) {
    registry.register(checkDefinition);
  }

  const runnable = registry.create(
    testSdk as unknown as SDK<object, object>,
    fullConfig,
  );

  const requestIDs = targets.map((t) => t.request.getId());
  await runnable.run(requestIDs);

  const history = runnable.getExecutionHistory();

  return history.map((record) => {
    const findings = record.steps.flatMap((step) => step.findings);
    const output =
      record.status === "completed" ? record.finalOutput : undefined;
    return { findings, output };
  });
}
