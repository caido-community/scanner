import type { ScanMetadata } from "engine";
import { ok, type Result } from "shared";

import { ChecksStore, type SelectOptions } from "../stores/checks";
import { type BackendSDK } from "../types";

export const getChecks = (
  _: BackendSDK,
  options?: Pick<SelectOptions, "type" | "include" | "exclude">,
): Result<ScanMetadata[]> => {
  const store = ChecksStore.get();
  const results = store.select({ ...options, returnMetadata: true });
  return ok(results);
};
