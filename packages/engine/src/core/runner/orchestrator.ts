import { type SDK } from "caido:plugin";
import { Graph, topologicalSort } from "graph-data-structure";

import {
  type CheckDefinition,
  type CheckTarget,
  type Finding,
  type ScanConfig,
  type ScanResult,
} from "../../types";
import { DependencyStore, HtmlCache } from "../runtime";

import { TargetProcessor } from "./processor";
import { type ScanRunner } from "./runner";

/**
 * ScanOrchestrator is responsible for managing the lifecycle and shared state of a single scan run.
 * It coordinates the processing of multiple targets and holds shared data like the dependency store,
 */
export class ScanOrchestrator {
  public readonly batches: CheckDefinition[][];
  public readonly dependencyStore = new DependencyStore();
  public readonly htmlCache = new HtmlCache();
  public readonly dedupeKeysCache = new Map<string, Set<string>>();
  public readonly runner: ScanRunner;
  public readonly sdk: SDK;
  public readonly config: ScanConfig;

  constructor(runner: ScanRunner, sdk: SDK, config: ScanConfig) {
    this.runner = runner;
    this.sdk = sdk;
    this.config = config;
    this.batches = this.getCheckBatches(runner.checks);
  }

  public async execute(targets: CheckTarget[]): Promise<ScanResult> {
    const allFindings: Finding[] = [];

    try {
      for (const target of targets) {
        if (this.runner.state === "Interrupted") {
          return {
            kind: "Interrupted",
            reason: "Cancelled",
          };
        }

        const processor = new TargetProcessor(target, this);
        const result = await processor.process();
        if (result.kind !== "Finished") {
          return result;
        }

        allFindings.push(...result.findings);
      }

      return {
        kind: "Finished",
        findings: allFindings,
      };
    } catch (error) {
      return {
        kind: "Error",
        error:
          error instanceof Error ? error.message : "Unknown error occurred",
      };
    }
  }

  private getCheckBatches(checks: CheckDefinition[]): CheckDefinition[][] {
    const graph = new Graph();
    const map = new Map(checks.map((check) => [check.metadata.id, check]));

    checks.forEach((check) => graph.addNode(check.metadata.id));

    checks.forEach((check) => {
      check.metadata.dependsOn?.forEach((dependencyId) => {
        if (!map.has(dependencyId)) {
          throw new Error(
            `Check '${check.metadata.id}' has unknown dependency '${dependencyId}'`,
          );
        }
        graph.addEdge(dependencyId, check.metadata.id);
      });
    });

    try {
      const order = topologicalSort(graph);
      return order.map((id) => [map.get(id)!]);
    } catch (e) {
      throw new Error("Circular dependency detected in checks");
    }
  }
}
