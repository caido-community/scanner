import { type CheckMetadata, Result } from "engine";
import type { GetChecksOptions, Result as ResultType } from "shared";

import { GetChecksOptionsSchema } from "../schemas";
import { ChecksStore } from "../stores/checks";
import { type BackendSDK } from "../types";
import { validateInput } from "../utils/validation";

export const getChecks = (
  _: BackendSDK,
  options: GetChecksOptions = {},
): ResultType<CheckMetadata[]> => {
  const validation = validateInput(GetChecksOptionsSchema, options);
  if (validation.kind === "Error") {
    return validation;
  }

  const store = ChecksStore.get();
  const results = store.select({ ...validation.value, returnMetadata: true });
  return Result.ok(results);
};
