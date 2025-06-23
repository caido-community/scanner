import type { DefineAPI } from "caido:plugin";
import { type Finding, ScanRunner, type ScanTarget } from "engine";

import exposedEnvScan from "./checks/exposed-env";
import jsonHtmlResponse from "./checks/json-html-response";
import openRedirectScan from "./checks/open-redirect";
import { getChecks } from "./services/checks";
import { getUserConfig, updateUserConfig } from "./services/config";
import { startActiveScan } from "./services/scanner";
import { ChecksStore } from "./stores/checks";
import { ConfigStore } from "./stores/config";
import { type BackendSDK } from "./types";

export type API = DefineAPI<{
  getChecks: typeof getChecks;
  getUserConfig: typeof getUserConfig;
  updateUserConfig: typeof updateUserConfig;
  startActiveScan: typeof startActiveScan;
}>;

export function init(sdk: BackendSDK) {
  sdk.api.register("getChecks", getChecks);
  sdk.api.register("getUserConfig", getUserConfig);
  sdk.api.register("updateUserConfig", updateUserConfig);
  sdk.api.register("startActiveScan", startActiveScan);

  const checksStore = ChecksStore.get();
  checksStore.register(exposedEnvScan, openRedirectScan, jsonHtmlResponse);

  sdk.events.onInterceptResponse(async (sdk, request, response) => {
    const configStore = ConfigStore.get();
    const config = configStore.getUserConfig();

    if (!config.passive.enabled) return;

    const passiveScans = checksStore.select({ type: "passive" });
    if (passiveScans.length === 0) {
      return;
    }

    const runner = new ScanRunner();
    runner.register(...passiveScans);

    const target: ScanTarget = {
      request,
      response,
    };

    const findings: Finding[] = await runner.run(sdk, [target], {
      strength: config.passive.strength,
    });

    for (const finding of findings) {
      if (finding.requestID === undefined) return;

      const request = await sdk.requests.get(finding.requestID);
      if (!request) return;

      sdk.findings.create({
        reporter: "Scanner: Passive",
        request: request.request,
        title: finding.name,
        description: finding.description,
      });
    }
  });
}
