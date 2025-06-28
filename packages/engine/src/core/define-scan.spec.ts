import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  type CheckContext,
  type CheckMetadata,
  continueWith,
  defineScan,
  done,
  type Finding,
} from "../index";
import {
  createBaseFinding,
  createBaseMetadata,
  createScanContext,
} from "../tests/factories";

describe("defineScan", () => {
  let baseMetadata: CheckMetadata;
  let context: CheckContext;
  let baseFinding: Finding;

  beforeEach(() => {
    baseMetadata = createBaseMetadata();
    context = createScanContext();
    baseFinding = createBaseFinding();
  });

  describe("Definition", () => {
    it("should return a scan definition with the provided metadata", () => {
      const scan = defineScan(() => ({ metadata: baseMetadata }));
      expect(scan.metadata).toEqual(baseMetadata);
    });
  });

  describe("Task Creation", () => {
    it("should throw an error if no steps are defined", () => {
      const scan = defineScan(() => ({ metadata: baseMetadata }));
      expect(() => scan.create(context)).toThrow("No steps defined for scan");
    });
  });

  describe("State Management", () => {
    it("should initialize state with the 'initState' function", async () => {
      const initState = () => ({ count: 100 });
      const stepMock = vi.fn().mockReturnValue(done());

      const scan = defineScan(({ step }) => {
        step("start", stepMock);
        return { metadata: baseMetadata, initState };
      });

      const task = scan.create(context);
      await task.tick();

      expect(stepMock).toHaveBeenCalledWith({ count: 100 }, context);
    });

    it("should pass state between steps", async () => {
      const secondStepMock = vi.fn().mockReturnValue(done());

      const scan = defineScan(({ step }) => {
        step("first", () =>
          continueWith({ state: { data: "test" }, nextStep: "second" }),
        );
        step("second", secondStepMock);
        return { metadata: baseMetadata };
      });

      const task = scan.create(context);
      await task.tick();
      await task.tick();

      expect(secondStepMock).toHaveBeenCalledWith({ data: "test" }, context);
    });

    it("should retain the last state if 'done' is called without a state", async () => {
      const outputMock = vi.fn();
      const initialState = { result: "initial" };

      const scan = defineScan(({ step }) => {
        step("execute", () => done());
        return {
          metadata: baseMetadata,
          initState: () => initialState,
          output: outputMock,
        };
      });

      const task = scan.create(context);
      await task.tick();
      task.getOutput();

      expect(outputMock).toHaveBeenCalledWith(initialState);
    });
  });

  describe("Execution Flow", () => {
    it("should execute a single step and finish", async () => {
      const scan = defineScan(({ step }) => {
        step("execute", () => done({ findings: [baseFinding] }));
        return { metadata: baseMetadata };
      });

      const task = scan.create(context);
      const result = await task.tick();

      expect(result.isDone).toBe(true);
      expect(result.findings).toEqual([baseFinding]);
      expect(task.getFindings()).toEqual([baseFinding]);
    });

    it("should execute multiple steps in sequence", async () => {
      const firstStepMock = vi
        .fn()
        .mockReturnValue(continueWith({ state: {}, nextStep: "second" }));
      const secondStepMock = vi
        .fn()
        .mockReturnValue(done({ findings: [baseFinding] }));

      const scan = defineScan(({ step }) => {
        step("first", firstStepMock);
        step("second", secondStepMock);
        return { metadata: baseMetadata };
      });

      const task = scan.create(context);
      const firstTickResult = await task.tick();
      const secondTickResult = await task.tick();

      expect(firstStepMock).toHaveBeenCalledTimes(1);
      expect(secondStepMock).toHaveBeenCalledTimes(1);
      expect(firstTickResult.isDone).toBe(false);
      expect(secondTickResult.isDone).toBe(true);
      expect(task.getFindings()).toEqual([baseFinding]);
    });

    it("should throw an error when trying to tick to an unknown step", async () => {
      const scan = defineScan(({ step }) => {
        step("start", () =>
          continueWith({ state: {}, nextStep: "nonexistent" }),
        );
        return { metadata: baseMetadata };
      });

      const task = scan.create(context);
      await task.tick();
      await expect(task.tick()).rejects.toThrow("Step nonexistent not found");
    });
  });

  describe("Output", () => {
    it("should call the output function with the final state", async () => {
      const outputMock = vi.fn().mockReturnValue({ custom: "output" });
      const finalState = { result: "success" };

      const scan = defineScan(({ step }) => {
        step("execute", () => done({ state: finalState }));
        return { metadata: baseMetadata, output: outputMock };
      });

      const task = scan.create(context);
      await task.tick();
      const outputResult = task.getOutput();

      expect(outputMock).toHaveBeenCalledWith(finalState);
      expect(outputResult).toEqual({ custom: "output" });
    });
  });
});
