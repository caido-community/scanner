import { type SDK } from "caido:plugin";

import { type Check } from "../types/check";
import {
  type ScanConfig,
  type ScanRegistry,
  type ScanRunnable,
} from "../types/runner";

import { ScanRegistryError, ScanRegistryErrorCode } from "./errors";
import { createRunnable } from "./runnable";

/**
 * Creates an in-memory registry for scan checks.
 *
 * Register checks first, then call `create(sdk, config)` to get a runnable scan.
 * This is the usual entry point when wiring the engine into the backend or tests.
 */
export const createRegistry = (): ScanRegistry => {
  const checks: Check[] = [];

  const register = (check: Check) => {
    checks.push(check);
  };

  const validate = () => {
    if (checks.length === 0) {
      throw new ScanRegistryError(
        "No checks registered",
        ScanRegistryErrorCode.NO_CHECKS_REGISTERED,
      );
    }

    for (const check of checks) {
      if (check.metadata.dependsOn) {
        for (const dependency of check.metadata.dependsOn) {
          if (!checks.some((c) => c.metadata.id === dependency)) {
            throw new ScanRegistryError(
              `Check ${check.metadata.id} depends on ${dependency} but it is not registered`,
              ScanRegistryErrorCode.CHECK_DEPENDENCY_NOT_FOUND,
            );
          }
        }
      }
    }
  };

  const create = (sdk: SDK, config: ScanConfig): ScanRunnable => {
    validate();

    return createRunnable({
      sdk,
      checks,
      config,
    });
  };

  return {
    register,
    create,
  };
};
