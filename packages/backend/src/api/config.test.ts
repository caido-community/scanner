import type { UserConfig } from "shared";
import { describe, expect, it, vi } from "vitest";

import { createMockSDK } from "../__tests__/mockSdk";
import { ConfigStore } from "../stores/config";

import { apiGetUserConfig, apiUpdateUserConfig } from "./config";

vi.mock("caido:utils", () => ({
  RequestSpec: class {},
}));

const baseConfig: UserConfig = {
  passive: {
    enabled: false,
    aggressivity: "medium",
    scopeIDs: [],
    concurrentTargets: 1,
    concurrentRequests: 1,
    overrides: [],
    severities: ["info"],
  },
  active: { overrides: [] },
  presets: [],
};

describe("apiGetUserConfig", () => {
  it("returns the current user config", () => {
    vi.spyOn(ConfigStore, "get").mockReturnValue({
      getUserConfig: () => baseConfig,
    } as unknown as ConfigStore);

    const result = apiGetUserConfig(createMockSDK() as never);

    expect(result).toEqual({ kind: "Ok", value: baseConfig });
  });
});

describe("apiUpdateUserConfig", () => {
  it("forwards the patch to the store", () => {
    const updateUserConfig = vi.fn();
    vi.spyOn(ConfigStore, "get").mockReturnValue({
      updateUserConfig,
    } as unknown as ConfigStore);

    const patch: Partial<UserConfig> = {
      defaultPresetName: "Light",
    };
    const result = apiUpdateUserConfig(createMockSDK() as never, patch);

    expect(result).toEqual({ kind: "Ok", value: undefined });
    expect(updateUserConfig).toHaveBeenCalledWith(patch);
  });
});
