import { type DefineEvents, type SDK } from "caido:plugin";

import { type API } from ".";

export type BackendSDK = SDK<API, BackendEvents>;
type BackendEvents = DefineEvents<{}>;
