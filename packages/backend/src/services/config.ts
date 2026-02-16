import { Result } from "engine";
import type { Result as ResultType, UserConfig } from "shared";

import { ConfigStore } from "../stores/config";
import { type BackendSDK } from "../types";

export const getUserConfig = (_: BackendSDK): ResultType<UserConfig> => {
  const store = ConfigStore.get();
  return Result.ok(store.getUserConfig());
};

export const updateUserConfig = (
  _: BackendSDK,
  config: Partial<UserConfig>,
): ResultType<void> => {
  const store = ConfigStore.get();
  store.updateUserConfig(config);
  return Result.ok(undefined);
};
