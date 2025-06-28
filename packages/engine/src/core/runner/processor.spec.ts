import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  createBaseFinding,
  createMockOrchestrator,
  createScanContext,
  createScanTarget,
} from "../../tests/factories";
import {
  type CheckDefinition,
  type CheckMetadata,
  type CheckTarget,
  type Finding,
  type JSONSerializable,
  ScanStrength,
  type ScanTask,
} from "../../types";

import { TargetProcessor } from "./processor";

const createMockScanDefinition = (
  overrides: Partial<Omit<CheckDefinition, "metadata">> & {
    metadata?: Partial<CheckMetadata>;
  } = {},
): CheckDefinition => {
  return {
    metadata: {
      id: "test-scan",
      name: "Test Scan",
      description: "Test scan description",
      tags: ["test"],
      aggressivity: { minRequests: 1, maxRequests: 1 },
      type: "passive",
      ...overrides.metadata,
    },
    create: overrides.create ?? vi.fn(),
    when: overrides.when,
    dedupeKey: overrides.dedupeKey,
  };
};

const createMockTask = (
  id: string,
  ticks: Array<{
    isDone: boolean;
    findings?: Finding[];
    output?: JSONSerializable;
  }>,
): ScanTask => {
  const tickMock = vi.fn();
  ticks.forEach((t) => tickMock.mockResolvedValueOnce(t));

  const getOutputMock = vi.fn(() => ticks[ticks.length - 1]?.output);

  return {
    id,
    tick: tickMock,
    getFindings: () => [],
    getOutput: getOutputMock,
    serialize: () => "",
  };
};

describe("TargetProcessor", () => {
  let target: CheckTarget;
  let context: ReturnType<typeof createScanContext>;

  beforeEach(() => {
    target = createScanTarget();
    context = createScanContext({ request: target.request });
  });

  describe("process", () => {
    it("should process batches in sequence and aggregate findings", async () => {
      const finding1 = createBaseFinding({ name: "finding-1" });
      const finding2 = createBaseFinding({ name: "finding-2" });

      const task1 = createMockTask("task-1", [
        { isDone: true, findings: [finding1] },
      ]);
      const task2 = createMockTask("task-2", [
        { isDone: true, findings: [finding2] },
      ]);

      const scan1 = createMockScanDefinition({ create: () => task1 });
      const scan2 = createMockScanDefinition({ create: () => task2 });

      const orchestrator = createMockOrchestrator([[scan1], [scan2]]);
      const processor = new TargetProcessor(target, orchestrator);

      const result = await processor.process();

      expect(result.kind).toBe("Finished");
      if (result.kind === "Finished") {
        expect(result.findings).toEqual([finding1, finding2]);
      }
      expect(task1.tick).toHaveBeenCalledTimes(1);
      expect(task2.tick).toHaveBeenCalledTimes(1);
    });
  });

  describe("processBatch", () => {
    it("should run a simple one-step task and collect findings", async () => {
      const finding = createBaseFinding();
      const task = createMockTask("task-1", [
        { isDone: true, findings: [finding] },
      ]);
      const scan = createMockScanDefinition({ create: () => task });
      const orchestrator = createMockOrchestrator([[scan]]);
      const processor = new TargetProcessor(target, orchestrator);

      const result = await processor.process();

      expect(result.kind).toBe("Finished");
      if (result.kind === "Finished") {
        expect(result.findings).toEqual([finding]);
      }
      expect(task.tick).toHaveBeenCalledOnce();
    });

    it("should handle a multi-step task", async () => {
      const task = createMockTask("task-1", [
        { isDone: false },
        { isDone: false },
        { isDone: true },
      ]);
      const scan = createMockScanDefinition({ create: () => task });
      const orchestrator = createMockOrchestrator([[scan]]);
      const processor = new TargetProcessor(target, orchestrator);

      await processor.process();

      expect(task.tick).toHaveBeenCalledTimes(3);
    });

    it("should store the output of a completed task in the dependency store", async () => {
      const output = { data: "some-result" };
      const scanId = "scan-1";

      const task = createMockTask(scanId, [{ isDone: true, output }]);
      const scan = createMockScanDefinition({
        metadata: { id: scanId },
        create: () => task,
      });
      const orchestrator = createMockOrchestrator([[scan]]);
      const processor = new TargetProcessor(target, orchestrator);

      await processor.process();

      expect(task.getOutput).toHaveBeenCalledOnce();
      expect(task.getOutput()).toEqual(output);
      expect(orchestrator.dependencyStore.set).toHaveBeenCalledWith(
        scanId,
        output,
      );
    });
  });

  describe("isScanApplicable", () => {
    it("should return true for a basic applicable scan", () => {
      const scan = createMockScanDefinition({});
      const orchestrator = createMockOrchestrator([]);
      const processor = new TargetProcessor(target, orchestrator);
      expect(processor["isScanApplicable"](scan, context)).toBe(true);
    });

    it("should return false if scan strength is below minimum", () => {
      const scan = createMockScanDefinition({
        metadata: { minStrength: ScanStrength.HIGH },
      });
      const orchestrator = createMockOrchestrator([]);
      orchestrator.config.strength = ScanStrength.MEDIUM;
      const processor = new TargetProcessor(target, orchestrator);
      expect(processor["isScanApplicable"](scan, context)).toBe(false);
    });

    it("should return false if 'when' condition is false", () => {
      const scan = createMockScanDefinition({ when: () => false });
      const orchestrator = createMockOrchestrator([]);
      const processor = new TargetProcessor(target, orchestrator);
      expect(processor["isScanApplicable"](scan, context)).toBe(false);
    });

    it("should return true if 'when' condition is true", () => {
      const scan = createMockScanDefinition({ when: () => true });
      const orchestrator = createMockOrchestrator([]);
      const processor = new TargetProcessor(target, orchestrator);
      expect(processor["isScanApplicable"](scan, context)).toBe(true);
    });

    it("should return false for a duplicate scan based on dedupeKey", () => {
      const scan = createMockScanDefinition({
        metadata: { id: "dedupe-scan" },
        dedupeKey: (c) => c.request.getPath(),
      });
      const orchestrator = createMockOrchestrator([]);
      const processor = new TargetProcessor(target, orchestrator);

      expect(processor["isScanApplicable"](scan, context)).toBe(true);
      expect(processor["isScanApplicable"](scan, context)).toBe(false);
    });
  });
});
