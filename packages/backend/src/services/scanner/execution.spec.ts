import { describe, expect, it, vi } from "vitest";

import { ChecksStore } from "../../stores/checks";
import { ConfigStore } from "../../stores/config";
import { ScannerStore } from "../../stores/scanner";

import { startActiveScan } from "./execution";

vi.mock("caido:utils", () => ({
  RequestSpec: class {},
}));

const payload = {
  requestIDs: ["req-123"],
  title: "Example scan",
  scanConfig: {
    aggressivity: "medium" as const,
    scopeIDs: [],
    concurrentChecks: 1,
    concurrentRequests: 1,
    concurrentTargets: 1,
    requestsDelayMs: 0,
    scanTimeout: 60,
    checkTimeout: 60,
    severities: ["info" as const],
  },
};

describe("startActiveScan", () => {
  it("fails before creating a session when a request does not exist", async () => {
    const createSession = vi.fn();
    const getRequest = vi.fn().mockResolvedValue(undefined);

    vi.spyOn(ConfigStore, "get").mockReturnValue({
      getUserConfig: () => ({
        passive: {
          enabled: false,
          aggressivity: "medium",
          scopeIDs: [],
          concurrentTargets: 1,
          concurrentRequests: 1,
          overrides: [],
          severities: ["info"],
        },
        active: {
          overrides: [],
        },
        presets: [],
      }),
    } as unknown as ConfigStore);

    vi.spyOn(ChecksStore, "get").mockReturnValue({
      select: () => [{ id: "check-1" } as never],
    } as unknown as ChecksStore);

    vi.spyOn(ScannerStore, "get").mockReturnValue({
      createSession,
    } as unknown as ScannerStore);

    const sdk = {
      requests: {
        get: getRequest,
      },
    } as never;

    const result = await startActiveScan(sdk, payload);

    expect(result).toEqual({
      kind: "Error",
      error: "Request req-123 not found",
    });
    expect(getRequest).toHaveBeenCalledWith("req-123");
    expect(createSession).not.toHaveBeenCalled();
  });
});
