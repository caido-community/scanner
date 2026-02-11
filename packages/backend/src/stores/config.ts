import type { Preset, UserConfig } from "shared";

import {
  PresetsStorage,
  type ProjectConfig,
  ProjectConfigStorage,
  SettingsStorage,
} from "../storage";
import type { BackendSDK } from "../types";

import {
  computeUpdatedConfig,
  createDefaultActiveConfig,
  createDefaultPassiveConfig,
  migratePassiveConfig,
} from "./config.utils";
import {
  BALANCED_PRESET,
  BUGBOUNTY_PRESET,
  HEAVY_PRESET,
  LIGHT_PRESET,
} from "./presets";

const createDefaultPresets = (): Preset[] => [
  LIGHT_PRESET,
  BALANCED_PRESET,
  HEAVY_PRESET,
  BUGBOUNTY_PRESET,
];

export class ConfigStore {
  private static instance?: ConfigStore;

  private config: UserConfig;
  private sdk!: BackendSDK;
  private presetsStorage!: PresetsStorage;
  private projectConfigStorage!: ProjectConfigStorage;
  private settingsStorage!: SettingsStorage;
  private currentProjectId?: string;
  private saveTimeout?: Timeout;

  private constructor() {
    const presets = createDefaultPresets();
    const lightPreset = presets[0];

    this.config = {
      passive: createDefaultPassiveConfig(),
      active: createDefaultActiveConfig(),
      presets,
    };

    if (lightPreset) {
      this.config.active.overrides = lightPreset.active;
      this.config.passive.overrides = lightPreset.passive;
    }
  }

  static get(): ConfigStore {
    if (!ConfigStore.instance) {
      ConfigStore.instance = new ConfigStore();
    }

    return ConfigStore.instance;
  }

  async initialize(sdk: BackendSDK): Promise<void> {
    this.sdk = sdk;
    this.presetsStorage = new PresetsStorage(sdk);
    this.projectConfigStorage = new ProjectConfigStorage(sdk);
    this.settingsStorage = new SettingsStorage(sdk);

    const project = await sdk.projects.getCurrent();
    this.currentProjectId = project?.getId();

    const savedPresets = await this.presetsStorage.load();
    if (savedPresets) {
      this.config.presets = savedPresets;
    } else {
      await this.presetsStorage.save(this.config.presets);
    }

    const savedSettings = await this.settingsStorage.load();
    if (savedSettings !== undefined) {
      this.config.defaultPresetName = savedSettings.defaultPresetName;
      this.config.requestTimeout = savedSettings.requestTimeout ?? 2 * 60;
    } else {
      this.config.requestTimeout = 2 * 60;
    }

    if (this.currentProjectId !== undefined) {
      await this.loadProjectConfig(this.currentProjectId);
    }
  }

  async switchProject(projectId: string | undefined): Promise<void> {
    this.currentProjectId = projectId;

    if (projectId !== undefined) {
      await this.loadProjectConfig(projectId);
    } else {
      this.config.passive = createDefaultPassiveConfig();
      this.config.active = createDefaultActiveConfig();
    }
  }

  private async loadProjectConfig(projectId: string): Promise<void> {
    const savedConfig = await this.projectConfigStorage.load(projectId);
    if (savedConfig !== undefined) {
      const legacyScopeIDs = await this.getAllScopeIDs();
      this.config.passive = migratePassiveConfig(
        savedConfig.passive,
        legacyScopeIDs,
      );
      this.config.active = {
        ...createDefaultActiveConfig(),
        ...savedConfig.active,
      };
      return;
    }

    const defaultPreset = this.getDefaultPreset();
    if (defaultPreset) {
      this.config.active.overrides = defaultPreset.active;
      this.config.passive.overrides = defaultPreset.passive;
    }
    this.saveProjectConfig();
  }

  private async getAllScopeIDs(): Promise<string[]> {
    try {
      const scopes = await this.sdk.scope.getAll();
      return scopes.map((scope) => scope.id);
    } catch {
      return [];
    }
  }

  private getDefaultPreset(): Preset | undefined {
    if (this.config.presets.length === 0) {
      return undefined;
    }

    if (this.config.defaultPresetName !== undefined) {
      const preset = this.config.presets.find(
        (p) => p.name === this.config.defaultPresetName,
      );
      if (preset !== undefined) {
        return preset;
      }
    }

    return this.config.presets[0];
  }

  private saveProjectConfig(): void {
    if (this.currentProjectId === undefined) return;

    if (this.saveTimeout !== undefined) {
      clearTimeout(this.saveTimeout);
    }

    this.saveTimeout = setTimeout(() => {
      if (this.currentProjectId === undefined) return;

      const projectConfig: ProjectConfig = {
        passive: this.config.passive,
        active: this.config.active,
      };

      this.projectConfigStorage.save(this.currentProjectId, projectConfig);
    }, 1000);
  }

  getUserConfig(): UserConfig {
    return { ...this.config };
  }

  updateUserConfig(config: Partial<UserConfig>): UserConfig {
    const updateResult = computeUpdatedConfig(this.config, config);
    this.config = updateResult.nextConfig;

    if (updateResult.presetsToSave !== undefined) {
      this.presetsStorage.save(updateResult.presetsToSave);
    }

    if (updateResult.settingsToSave !== undefined) {
      this.settingsStorage.save(updateResult.settingsToSave);
    }

    this.saveProjectConfig();
    this.sdk.api.send("config:updated", this.currentProjectId);

    return this.config;
  }
}
