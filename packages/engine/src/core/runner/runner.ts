import { type SDK } from "caido:plugin";

import {
  type CheckDefinition,
  type CheckTarget,
  type ScanConfig,
  type ScanResult,
  type ScanState,
} from "../../types";

import { ScanOrchestrator } from "./orchestrator";

/**
 * ScanRunner is responsible for registering scan definitions and initiating scan runs.
 * It acts as the public API for the scanning engine.
 */
export class ScanRunner {
  public readonly checks: CheckDefinition[] = [];
  public state: ScanState = "Idle";
  private orchestrator: ScanOrchestrator | undefined;

  public register(...checks: CheckDefinition[]): void {
    if (this.state !== "Idle") {
      throw new Error("Cannot register checks while scan is running");
    }

    for (const check of checks) {
      if (this.checks.some((s) => s.metadata.id === check.metadata.id)) {
        throw new Error(
          `Scan with id '${check.metadata.id}' already registered`,
        );
      }
      this.checks.push(check);
    }
  }

  public stop(): void {
    if (this.state !== "Running") {
      throw new Error("Scan not running");
    }

    this.state = "Interrupted";
  }

  public async start(
    sdk: SDK,
    targets: CheckTarget[],
    config: ScanConfig,
  ): Promise<ScanResult> {
    if (this.state !== "Idle") {
      throw new Error("Scan already running");
    }

    if (this.checks.length === 0) {
      throw new Error("No checks registered");
    }

    if (targets.length === 0) {
      throw new Error("No targets provided");
    }

    this.state = "Running";

    try {
      this.orchestrator = new ScanOrchestrator(this, sdk, config);
      const result = await this.orchestrator.execute(targets);

      this.state = result.kind === "Finished" ? "Finished" : "Interrupted";
      return result;
    } catch (error) {
      this.state = "Error";
      return {
        kind: "Error",
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }
}
