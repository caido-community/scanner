import { ScanAggressivity } from "engine";
import type { ActiveConfig, PassiveConfig, Preset, UserConfig } from "shared";

export const createDefaultPassiveConfig = (): PassiveConfig => ({
  enabled: true,
  aggressivity: ScanAggressivity.LOW,
  scopeIDs: [],
  concurrentChecks: 2,
  concurrentRequests: 3,
  overrides: [],
  severities: ["critical", "high", "medium", "low", "info"],
});

type LegacyPassiveConfig = Partial<PassiveConfig> & {
  inScopeOnly?: boolean;
};

export const migratePassiveConfig = (
  passive: LegacyPassiveConfig,
  legacyScopeIDs: string[],
): PassiveConfig => {
  const { inScopeOnly: _legacyInScopeOnly, ...restPassive } = passive;

  const scopeIDs = Array.isArray(passive.scopeIDs)
    ? passive.scopeIDs.filter((scopeID): scopeID is string => {
        return typeof scopeID === "string";
      })
    : passive.inScopeOnly === true
      ? legacyScopeIDs
      : [];

  return {
    ...createDefaultPassiveConfig(),
    ...restPassive,
    scopeIDs,
  };
};

export const createDefaultActiveConfig = (): ActiveConfig => ({
  overrides: [],
});

type ComputeUpdatedConfigResult = {
  nextConfig: UserConfig;
  presetsToSave?: Preset[];
  settingsToSave?: {
    defaultPresetName: string | undefined;
  };
};

export const computeUpdatedConfig = (
  currentConfig: UserConfig,
  configPatch: Partial<UserConfig>,
): ComputeUpdatedConfigResult => {
  const nextConfig: UserConfig = {
    ...currentConfig,
    ...configPatch,
  };

  if (configPatch.presets !== undefined) {
    if (
      nextConfig.defaultPresetName !== undefined &&
      !nextConfig.presets.some((p) => p.name === nextConfig.defaultPresetName)
    ) {
      const firstPreset = nextConfig.presets[0];
      nextConfig.defaultPresetName =
        firstPreset !== undefined ? firstPreset.name : undefined;
    }
  }

  if (configPatch.defaultPresetName !== undefined) {
    if (
      !nextConfig.presets.some((p) => p.name === configPatch.defaultPresetName)
    ) {
      const firstPreset = nextConfig.presets[0];
      nextConfig.defaultPresetName =
        firstPreset !== undefined ? firstPreset.name : undefined;
    } else {
      nextConfig.defaultPresetName = configPatch.defaultPresetName;
    }
  }

  const defaultPresetNameChanged =
    currentConfig.defaultPresetName !== nextConfig.defaultPresetName;
  const shouldPersistSettings =
    configPatch.defaultPresetName !== undefined ||
    (configPatch.presets !== undefined && defaultPresetNameChanged);

  return {
    nextConfig,
    presetsToSave: configPatch.presets,
    settingsToSave: shouldPersistSettings
      ? {
          defaultPresetName: nextConfig.defaultPresetName,
        }
      : undefined,
  };
};
