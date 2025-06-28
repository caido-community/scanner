import { type CheckMetadata } from "engine";

export type ChecksState =
  | { type: "Idle" }
  | { type: "Loading" }
  | { type: "Error"; error: string }
  | { type: "Success"; checks: CheckMetadata[] };
