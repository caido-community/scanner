import { defineStore } from "pinia";
import { type DeepPartial, type UserConfig } from "shared";
import { merge } from "ts-deepmerge";

import { useSDK } from "@/plugins/sdk";
import { useConfigRepository } from "@/repositories/config";
import { useConfigStore } from "@/stores/config";

export const useConfigService = defineStore("services.config", () => {
  const sdk = useSDK();
  const repository = useConfigRepository();
  const store = useConfigStore();

  const getState = () => store.getState();

  const initialize = async () => {
    store.send({ type: "Start" });

    const result = await repository.getConfig();

    if (result.kind === "Ok") {
      store.send({ type: "Success", config: result.value });
    } else {
      store.send({ type: "Error", error: result.error });
      sdk.window.showToast("Failed to load configuration", {
        variant: "error",
      });
    }

    sdk.backend.onEvent("project:changed", async () => {
      store.send({ type: "Start" });
      const result = await repository.getConfig();

      if (result.kind === "Ok") {
        store.send({ type: "Success", config: result.value });
      } else {
        store.send({ type: "Error", error: result.error });
      }
    });

    sdk.backend.onEvent("config:updated", async () => {
      const result = await repository.getConfig();

      if (result.kind === "Ok") {
        store.send({ type: "Success", config: result.value });
      }
    });
  };

  const updateConfig = async (update: DeepPartial<UserConfig>) => {
    const currState = store.getState();
    if (currState.type === "Success") {
      const updatedConfig = merge.withOptions(
        { mergeArrays: false },
        currState.config,
        update,
      ) as UserConfig;
      const result = await repository.updateConfig(updatedConfig);
      if (result.kind === "Ok") {
        store.send({ type: "UpdateConfig", config: updatedConfig });
      } else {
        store.send({ type: "Error", error: result.error });
        sdk.window.showToast("Failed to update configuration", {
          variant: "error",
        });
      }
    }
  };

  return {
    getState,
    initialize,
    updateConfig,
  };
});
