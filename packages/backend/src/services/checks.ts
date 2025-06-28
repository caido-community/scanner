import type { CheckMetadata } from "engine";
import { type GetChecksOptions, ok, type Result } from "shared";

import { ChecksStore } from "../stores/checks";
import { type BackendSDK } from "../types";

export const getChecks = (
  _: BackendSDK,
  options: GetChecksOptions = {},
): Result<CheckMetadata[]> => {
  const store = ChecksStore.get();
  const results = store.select({ ...options, returnMetadata: true });
  return ok(results);
};
