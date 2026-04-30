import type { SDK } from "caido:plugin";
import type { Result, UserConfig } from "shared";

import { getUserConfig, updateUserConfig } from "../services/config";

export const apiGetUserConfig = (_sdk: SDK): Result<UserConfig> =>
  getUserConfig();

export const apiUpdateUserConfig = (
  _sdk: SDK,
  config: Partial<UserConfig>,
): Result<void> => updateUserConfig(config);
