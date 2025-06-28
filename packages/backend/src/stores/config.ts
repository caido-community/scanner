import { ScanStrength } from "engine";
import { type UserConfig } from "shared";

export class ConfigStore {
  private static _store?: ConfigStore;

  private config: UserConfig;

  private constructor() {
    this.config = {
      passive: {
        enabled: false,
        strength: ScanStrength.HIGH,
        overrides: {},
      },
      active: {
        overrides: {},
      },
    };
  }

  static get(): ConfigStore {
    if (!ConfigStore._store) {
      ConfigStore._store = new ConfigStore();
    }

    return ConfigStore._store;
  }

  getUserConfig() {
    return { ...this.config };
  }

  updateUserConfig(config: Partial<UserConfig>) {
    Object.assign(this.config, config);
    return this.config;
  }
}
