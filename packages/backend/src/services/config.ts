import { Result, type UserConfig } from "shared";

import { ConfigStore } from "../stores/config";

export const getUserConfig = (): Result<UserConfig> => {
  const store = ConfigStore.get();
  return Result.ok(store.getUserConfig());
};

export const updateUserConfig = (config: Partial<UserConfig>): Result<void> => {
  const store = ConfigStore.get();
  store.updateUserConfig(config);
  return Result.ok(undefined);
};
