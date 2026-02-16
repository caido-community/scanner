import path from "path";

import type { BackendSDK } from "../types";

import { BaseStorage } from "./base";

type UserSettings = {
  defaultPresetName?: string;
  requestTimeout?: number;
};

export class SettingsStorage extends BaseStorage {
  constructor(sdk: BackendSDK) {
    super(sdk);
  }

  private getFilePath(): string {
    return path.join(this.getBasePath(), "config", "settings.json");
  }

  async load(): Promise<UserSettings | undefined> {
    return this.readJson<UserSettings>(this.getFilePath());
  }

  async save(settings: UserSettings): Promise<void> {
    try {
      await this.writeJson(this.getFilePath(), settings);
    } catch (error) {
      this.sdk.console.error(`Failed to save settings: ${error}`);
    }
  }
}
