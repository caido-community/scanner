import { type SDK } from "caido:plugin";
import { type Request, type Response } from "caido:utils";
import { vi } from "vitest";

import { type ScanOrchestrator } from "../core/runner/orchestrator";
import {
  type CheckContext,
  type CheckDefinition,
  type CheckMetadata,
  type CheckTarget,
  defineScan,
  type Finding,
  type ScanRunner,
  ScanStrength,
  Severity,
} from "../index";
import type { ScanRuntime } from "../types/runtime";

export const createMockSDK = (): SDK => ({}) as SDK;

export const createBaseFinding = (
  overrides: Partial<Finding> = {},
): Finding => ({
  name: "test-finding",
  description: "Test finding description",
  severity: Severity.INFO,
  requestID: "123",
  ...overrides,
});

export const createBaseMetadata = (
  overrides: Partial<CheckMetadata> = {},
): CheckMetadata => ({
  id: "test-scan",
  name: "Test Scan",
  description: "Test scan description",
  tags: ["test"],
  aggressivity: { minRequests: 1, maxRequests: 1 },
  type: "passive" as const,
  ...overrides,
});

export const createMockRequest = ({
  host = "example.com",
  path = "/test",
  id = "req-123",
} = {}): Request =>
  ({
    getHost: () => host,
    getPath: () => path,
    getId: () => id,
  }) as unknown as Request;

export const createMockResponse = ({ id = "resp-123" } = {}): Response =>
  ({
    getId: () => id,
  }) as unknown as Response;

export const createScanTarget = (
  overrides: Partial<CheckTarget> = {},
): CheckTarget => ({
  request: createMockRequest(),
  response: createMockResponse(),
  ...overrides,
});

export const createScanContext = (
  overrides: Partial<CheckContext> = {},
): CheckContext => ({
  request: createMockRequest(),
  response: createMockResponse(),
  sdk: createMockSDK(),
  runtime: {
    dependencies: {
      get: vi.fn(),
    },
    html: {
      get: vi.fn(),
    },
  } as unknown as ScanRuntime,
  config: { strength: ScanStrength.HIGH },
  ...overrides,
});

export const createMockScanDefinition = (
  overrides: Partial<Omit<CheckDefinition, "metadata">> & {
    metadata?: Partial<CheckMetadata>;
  } = {},
): CheckDefinition => {
  const { metadata: metadataOverrides, ...restOverrides } = overrides;
  const metadata = createBaseMetadata(metadataOverrides);

  return defineScan(() => ({
    metadata,
    ...restOverrides,
  }));
};

export const createMockOrchestrator = (
  batches: CheckDefinition[][],
): ScanOrchestrator => {
  return {
    batches,
    sdk: {} as SDK,
    runner: {
      state: "Running",
    } as unknown as ScanRunner,
    config: { strength: ScanStrength.HIGH },
    dependencyStore: {
      set: vi.fn(),
      get: vi.fn(),
    },
    htmlCache: {
      get: vi.fn(),
    },
    dedupeKeysCache: new Map(),
  } as unknown as ScanOrchestrator;
};
