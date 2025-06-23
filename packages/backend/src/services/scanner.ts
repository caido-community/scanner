import { type Finding, ScanRunner, type ScanTarget } from "engine";
import { error, ok, type Result } from "shared";

import { ChecksStore } from "../stores/checks";
import { ConfigStore } from "../stores/config";
import { type BackendSDK } from "../types";

// TODO: this should return a scanID and run in background
export const startActiveScan = async (
  sdk: BackendSDK,
  ...targets: ScanTarget[]
): Promise<Result<Finding[]>> => {
  if (targets.length === 0) {
    return error("No targets provided");
  }

  const checksStore = ChecksStore.get();
  const activeScans = checksStore.select({ type: "active" });
  if (activeScans.length === 0) {
    return error("No active scans available");
  }

  const runner = new ScanRunner();
  runner.register(...activeScans);

  const configStore = ConfigStore.get();
  const config = configStore.getUserConfig();

  const findings: Finding[] = await runner.run(sdk, targets, {
    strength: config.passive.strength,
  });

  return ok(findings);
};
