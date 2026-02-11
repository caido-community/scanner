import { type ScanAggressivity, type Severity } from "engine";
import type { Preset } from "shared";
import { computed, type Ref } from "vue";

import { useSDK } from "@/plugins/sdk";
import { useConfigService } from "@/services/config";
import { type ConfigState } from "@/types/config";

export const useForm = (state: Ref<ConfigState & { type: "Success" }>) => {
  const configService = useConfigService();
  const sdk = useSDK();

  const passiveEnabled = computed({
    get: () => state.value.config.passive.enabled,
    set: async (value: boolean) => {
      await configService.updateConfig({
        passive: { enabled: value },
      });
    },
  });

  const passiveAggressivity = computed({
    get: () => state.value.config.passive.aggressivity,
    set: async (value: ScanAggressivity) => {
      await configService.updateConfig({
        passive: { aggressivity: value },
      });
    },
  });

  const passiveScopeIDs = computed({
    get: () => state.value.config.passive.scopeIDs,
    set: async (value: string[]) => {
      await configService.updateConfig({
        passive: { scopeIDs: value },
      });
    },
  });

  const passiveConcurrentScans = computed({
    get: () => state.value.config.passive.concurrentChecks,
    set: async (value: number) => {
      await configService.updateConfig({
        passive: { concurrentChecks: value },
      });
    },
  });

  const passiveConcurrentRequests = computed({
    get: () => state.value.config.passive.concurrentRequests,
    set: async (value: number) => {
      await configService.updateConfig({
        passive: { concurrentRequests: value },
      });
    },
  });

  const passiveSeverities = computed({
    get: () => state.value.config.passive.severities,
    set: async (value: Severity[]) => {
      await configService.updateConfig({
        passive: { severities: value },
      });
    },
  });

  const defaultPresetName = computed({
    get: () => state.value.config.defaultPresetName,
    set: async (value: string | undefined) => {
      await configService.updateConfig({
        defaultPresetName: value,
      });
    },
  });

  const requestTimeout = computed({
    get: () => state.value.config.requestTimeout,
    set: async (value: number | null | undefined) => {
      await configService.updateConfig({
        requestTimeout: value ?? undefined,
      });
    },
  });

  const presets = computed(() => state.value.config.presets);

  const presetOptions = computed(() => {
    return presets.value.map((preset: Preset) => ({
      label: preset.name,
      value: preset.name,
    }));
  });

  const scopeOptions = sdk.scopes.getScopes().map((scope) => ({
    label: scope.name,
    value: scope.id,
  }));

  return {
    passiveEnabled,
    passiveAggressivity,
    passiveScopeIDs,
    passiveConcurrentScans,
    passiveConcurrentRequests,
    passiveSeverities,
    defaultPresetName,
    requestTimeout,
    presetOptions,
    scopeOptions,
  };
};
