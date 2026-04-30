import type { DefinePluginPackageSpec } from "@caido/sdk-shared";

import type { API } from "./api";
import type { Events } from "./events";

export type { API } from "./api";
export type { Events } from "./events";

export * from "./check";
export * from "./config";
export * from "./finding";
export * from "./queue";
export * from "./request";
export * from "./result";
export * from "./scan";
export * from "./session";
export * from "./severity";
export * from "./utils";

export type Spec = DefinePluginPackageSpec<{
  manifestId: "scanner";
  api: API;
  events: Events;
}>;
