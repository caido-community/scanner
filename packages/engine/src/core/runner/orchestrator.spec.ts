import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  createBaseFinding,
  createMockScanDefinition,
  createMockSDK,
  createScanTarget,
} from "../../tests/factories";
import {
  type CheckDefinition,
  type CheckTarget,
  type ScanConfig,
  ScanStrength,
} from "../../types";

import { ScanOrchestrator } from "./orchestrator";
import { TargetProcessor } from "./processor";
import { ScanRunner } from "./runner";

vi.mock("./processor");

describe("ScanOrchestrator", () => {
  let sdk: ReturnType<typeof createMockSDK>;
  let config: ScanConfig;
  let scans: CheckDefinition[];

  beforeEach(() => {
    sdk = createMockSDK();
    config = { strength: ScanStrength.HIGH };
    scans = [];
    vi.clearAllMocks();
  });

  describe("constructor and dependency resolution", () => {
    it("should correctly order scans based on dependencies", () => {
      const scanA = createMockScanDefinition({ metadata: { id: "A" } });
      const scanB = createMockScanDefinition({
        metadata: { id: "B", dependsOn: ["A"] },
      });
      const scanC = createMockScanDefinition({
        metadata: { id: "C", dependsOn: ["B"] },
      });

      const runner = new ScanRunner();
      runner.register(scanC, scanA, scanB);
      runner.state = "Running";

      const orchestrator = new ScanOrchestrator(runner, sdk, config);
      const batchIds = orchestrator.batches.flat().map((s) => s.metadata.id);

      expect(batchIds).toEqual(["A", "B", "C"]);
    });

    it("should throw an error for unknown dependencies", () => {
      const scanA = createMockScanDefinition({
        metadata: { id: "A", dependsOn: ["UNKNOWN"] },
      });
      const runner = new ScanRunner();
      runner.register(scanA);

      expect(() => new ScanOrchestrator(runner, sdk, config)).toThrow(
        "Check 'A' has unknown dependency 'UNKNOWN'",
      );
    });

    it("should throw an error for circular dependencies", () => {
      const scanA = createMockScanDefinition({
        metadata: { id: "A", dependsOn: ["B"] },
      });
      const scanB = createMockScanDefinition({
        metadata: { id: "B", dependsOn: ["A"] },
      });

      const runner = new ScanRunner();
      runner.register(scanA, scanB);

      expect(() => new ScanOrchestrator(runner, sdk, config)).toThrow(
        "Circular dependency detected in checks",
      );
    });
  });

  describe("execute", () => {
    it("should process each target and aggregate findings", async () => {
      const targets: CheckTarget[] = [createScanTarget(), createScanTarget()];
      const finding1 = createBaseFinding({ name: "finding-1" });
      const finding2 = createBaseFinding({ name: "finding-2" });

      const mockProcess = vi
        .fn()
        .mockResolvedValueOnce({ kind: "Finished", findings: [finding1] })
        .mockResolvedValueOnce({ kind: "Finished", findings: [finding2] });

      vi.mocked(TargetProcessor).mockImplementation(
        () => ({ process: mockProcess }) as unknown as TargetProcessor,
      );

      const runner = new ScanRunner();
      runner.register(...scans);
      runner.state = "Running";

      const orchestrator = new ScanOrchestrator(runner, sdk, config);
      const result = await orchestrator.execute(targets);

      expect(TargetProcessor).toHaveBeenCalledTimes(2);
      expect(mockProcess).toHaveBeenCalledTimes(2);
      expect(result.kind).toBe("Finished");
      if (result.kind === "Finished") {
        expect(result.findings).toHaveLength(2);
        expect(result.findings).toEqual([finding1, finding2]);
      }
    });

    it("should return an empty array if no targets are provided", async () => {
      const runner = new ScanRunner();
      runner.register(...scans);

      const orchestrator = new ScanOrchestrator(runner, sdk, config);
      const result = await orchestrator.execute([]);

      expect(TargetProcessor).not.toHaveBeenCalled();
      expect(result.kind).toBe("Finished");
      if (result.kind === "Finished") {
        expect(result.findings).toEqual([]);
      }
    });
  });
});
