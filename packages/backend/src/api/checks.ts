import type { SDK } from "caido:plugin";
import type { CheckMetadata, GetChecksOptions, Result } from "shared";

import { getChecks } from "../services/checks";

export const apiGetChecks = (
  _sdk: SDK,
  options?: GetChecksOptions,
): Result<CheckMetadata[]> => getChecks(options);
