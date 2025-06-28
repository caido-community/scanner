import { ScanStrength } from "engine";
import { computed, type Ref } from "vue";

import { useConfigService } from "@/services/config";
import { type ConfigState } from "@/types/config";

type UseFormProps = {
  state: Ref<ConfigState>;
};

export const useForm = ({ state }: UseFormProps) => {
  const configService = useConfigService();

  const strengthOptions = [
    { label: "Low", value: ScanStrength.LOW },
    { label: "Medium", value: ScanStrength.MEDIUM },
    { label: "High", value: ScanStrength.HIGH },
  ];

  const passiveEnabled = computed({
    get: () => {
      return state.value.type === "Success"
        ? state.value.config.passive.enabled
        : false;
    },
    set: async (value: boolean) => {
      await configService.updateConfig({
        passive: {
          enabled: value,
          strength:
            state.value.type === "Success"
              ? state.value.config.passive.strength
              : ScanStrength.MEDIUM,
          overrides:
            state.value.type === "Success"
              ? state.value.config.passive.overrides
              : {},
        },
      });
    },
  });

  const passiveStrength = computed({
    get: () => {
      return state.value.type === "Success"
        ? state.value.config.passive.strength
        : ScanStrength.MEDIUM;
    },
    set: async (value: ScanStrength) => {
      await configService.updateConfig({
        passive: {
          enabled:
            state.value.type === "Success"
              ? state.value.config.passive.enabled
              : false,
          strength: value,
          overrides:
            state.value.type === "Success"
              ? state.value.config.passive.overrides
              : {},
        },
      });
    },
  });

  return {
    passiveEnabled,
    passiveStrength,
    strengthOptions,
  };
};
