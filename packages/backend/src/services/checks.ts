import { type CheckMetadata, type GetChecksOptions, Result } from "shared";

import { GetChecksOptionsSchema } from "../schemas";
import { ChecksStore } from "../stores/checks";
import { validateInput } from "../utils/validation";

export const getChecks = (
  options: GetChecksOptions = {},
): Result<CheckMetadata[]> => {
  const validation = validateInput(GetChecksOptionsSchema, options);
  if (validation.kind === "Error") {
    return validation;
  }

  const store = ChecksStore.get();
  const results = store.select({ ...validation.value, returnMetadata: true });
  return Result.ok(results);
};
