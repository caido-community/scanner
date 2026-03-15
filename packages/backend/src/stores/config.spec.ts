import type { Preset, UserConfig } from "shared";
import { describe, expect, it } from "vitest";

import {
  computeUpdatedConfig,
  createDefaultActiveConfig,
  createDefaultPassiveConfig,
  migratePassiveConfig,
} from "./config.utils";

const createPreset = (name: string): Preset => ({
  name,
  active: [],
  passive: [],
});

const createUserConfig = (): UserConfig => ({
  passive: createDefaultPassiveConfig(),
  active: createDefaultActiveConfig(),
  presets: [
    createPreset("Light"),
    createPreset("Balanced"),
    createPreset("Heavy"),
  ],
  defaultPresetName: "Balanced",
});

describe("migratePassiveConfig", () => {
  it("uses legacy scope IDs when inScopeOnly is true and scopeIDs is missing", () => {
    const result = migratePassiveConfig(
      {
        enabled: false,
        inScopeOnly: true,
      },
      ["scope-a", "scope-b"],
    );

    expect(result.enabled).toBe(false);
    expect(result.scopeIDs).toEqual(["scope-a", "scope-b"]);
  });

  it("filters non-string scope IDs from legacy config", () => {
    const result = migratePassiveConfig(
      {
        scopeIDs: ["scope-a", 1 as unknown as string, "scope-b"],
      },
      [],
    );

    expect(result.scopeIDs).toEqual(["scope-a", "scope-b"]);
  });

  it("fills missing values with defaults", () => {
    const result = migratePassiveConfig(
      {
        concurrentChecks: 10,
      },
      [],
    );

    expect(result.concurrentTargets).toBe(10);
    expect(result.concurrentRequests).toBe(3);
    expect(result.severities).toEqual([
      "critical",
      "high",
      "medium",
      "low",
      "info",
    ]);
  });

  it("preserves explicit concurrentTargets when present", () => {
    const result = migratePassiveConfig(
      {
        concurrentChecks: 10,
        concurrentTargets: 4,
      },
      [],
    );

    expect(result.concurrentTargets).toBe(4);
  });
});

describe("computeUpdatedConfig", () => {
  it("updates presets and reassigns invalid default preset", () => {
    const current = createUserConfig();
    const newPresets = [createPreset("Only")];

    const result = computeUpdatedConfig(current, {
      presets: newPresets,
    });

    expect(result.nextConfig.presets).toEqual(newPresets);
    expect(result.nextConfig.defaultPresetName).toBe("Only");
    expect(result.presetsToSave).toEqual(newPresets);
    expect(result.settingsToSave).toEqual({
      defaultPresetName: "Only",
    });
  });

  it("accepts explicit default preset when it exists", () => {
    const current = createUserConfig();

    const result = computeUpdatedConfig(current, {
      defaultPresetName: "Heavy",
    });

    expect(result.nextConfig.defaultPresetName).toBe("Heavy");
    expect(result.settingsToSave).toEqual({
      defaultPresetName: "Heavy",
    });
  });

  it("falls back to first preset when explicit default preset is invalid", () => {
    const current = createUserConfig();

    const result = computeUpdatedConfig(current, {
      defaultPresetName: "Missing",
    });

    expect(result.nextConfig.defaultPresetName).toBe("Light");
    expect(result.settingsToSave).toEqual({
      defaultPresetName: "Light",
    });
  });

  it("does not persist settings when presets update keeps current default valid", () => {
    const current = createUserConfig();

    const result = computeUpdatedConfig(current, {
      presets: [createPreset("Balanced"), createPreset("Extra")],
    });

    expect(result.nextConfig.defaultPresetName).toBe("Balanced");
    expect(result.settingsToSave).toBeUndefined();
  });
});
