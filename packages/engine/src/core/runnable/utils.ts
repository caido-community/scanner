import { batchingToposort } from "batching-toposort-ts";

import { type Check } from "../../types/check";
import type { Result } from "../../types/result";
import { Result as ResultHelpers } from "../../types/result";
import {
  type InterruptReason,
  type RuntimeContext,
  type ScanAggressivity,
} from "../../types/runner";

export type CheckDedupeRecord = {
  checkID: string;
  key: string;
};

type CheckApplicabilityError =
  | "severity"
  | "aggressivity"
  | "when"
  | "duplicate-dedupe-key";

type CheckApplicabilityResult = Result<
  {
    dedupeRecord?: CheckDedupeRecord;
  },
  CheckApplicabilityError
>;

const aggressivityPriority: Record<ScanAggressivity, number> = {
  low: 0,
  medium: 1,
  high: 2,
};

const hasRequiredAggressivity = ({
  minAggressivity,
  aggressivity,
}: {
  minAggressivity?: ScanAggressivity;
  aggressivity: ScanAggressivity;
}): boolean => {
  if (minAggressivity === undefined) {
    return true;
  }

  return (
    aggressivityPriority[minAggressivity] <= aggressivityPriority[aggressivity]
  );
};

/**
 * Checks whether a check should run for the current target and scan config.
 *
 * Use this when you need the reason a check was skipped, or when you want the
 * dedupe key that would be reserved if the check is allowed to run.
 */
export const evaluateCheckApplicability = ({
  check,
  context,
  dedupeKeys,
}: {
  check: Check;
  context: RuntimeContext;
  dedupeKeys: Map<string, Set<string>>;
}): CheckApplicabilityResult => {
  if (
    !check.metadata.severities.some((severity) =>
      context.config.severities.includes(severity),
    )
  ) {
    return ResultHelpers.err("severity");
  }

  if (
    !hasRequiredAggressivity({
      minAggressivity: check.metadata.minAggressivity,
      aggressivity: context.config.aggressivity,
    })
  ) {
    return ResultHelpers.err("aggressivity");
  }

  if (check.when !== undefined && !check.when(context.target)) {
    return ResultHelpers.err("when");
  }

  if (check.dedupeKey === undefined) {
    return ResultHelpers.ok({});
  }

  const checkID = check.metadata.id;
  const key = check.dedupeKey(context.target);
  const checkCache = dedupeKeys.get(checkID);
  if (checkCache !== undefined && checkCache.has(key)) {
    return ResultHelpers.err("duplicate-dedupe-key");
  }

  return ResultHelpers.ok({
    dedupeRecord: {
      checkID,
      key,
    },
  });
};

/**
 * Applies the applicability rules for a check and reserves its dedupe key.
 *
 * This is the boolean version used during scheduling. It returns `true` when the
 * check can run and updates the dedupe map if the check defines a dedupe key.
 */
export const applyCheckApplicability = ({
  check,
  context,
  dedupeKeys,
}: {
  check: Check;
  context: RuntimeContext;
  dedupeKeys: Map<string, Set<string>>;
}): boolean => {
  const applicability = evaluateCheckApplicability({
    check,
    context,
    dedupeKeys,
  });

  if (ResultHelpers.isErr(applicability)) {
    return false;
  }

  if (applicability.value.dedupeRecord !== undefined) {
    let checkCache = dedupeKeys.get(applicability.value.dedupeRecord.checkID);
    if (checkCache === undefined) {
      checkCache = new Set<string>();
      dedupeKeys.set(applicability.value.dedupeRecord.checkID, checkCache);
    }
    checkCache.add(applicability.value.dedupeRecord.key);
  }

  return true;
};

/**
 * Clones the current dedupe-key map.
 *
 * Use this when applicability needs to be evaluated without mutating the original
 * dedupe state for the full scan.
 */
export const createDedupeKeysSnapshot = (
  dedupeKeys: Map<string, Set<string>>,
): Map<string, Set<string>> => {
  const snapshot = new Map<string, Set<string>>();
  for (const [checkId, keySet] of dedupeKeys) {
    snapshot.set(checkId, new Set(keySet));
  }
  return snapshot;
};

/**
 * Detects whether a thrown error came from scan interruption.
 *
 * This is used to distinguish expected cancellation from regular task failures.
 */
export const isInterruptCancellationError = ({
  interruptReason,
  error,
}: {
  interruptReason: InterruptReason | undefined;
  error: unknown;
}): boolean => {
  return (
    interruptReason !== undefined &&
    error instanceof Error &&
    error.message === interruptReason
  );
};

/**
 * Runs an async operation with a timeout.
 *
 * Pass the work in `run()` and use `onTimeout()` to perform any cleanup when the
 * time limit is hit.
 */
export const withTimeout = async <T>({
  timeoutMs,
  onTimeout,
  run,
}: {
  timeoutMs: number;
  onTimeout: () => void;
  run: () => Promise<T>;
}): Promise<T> => {
  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timeoutId = setTimeout(() => {
      onTimeout();
      reject(new Error("timeout"));
    }, timeoutMs);
  });

  return await Promise.race([run(), timeoutPromise]).finally(() => {
    if (timeoutId !== undefined) {
      clearTimeout(timeoutId);
    }
  });
};

/**
 * Groups checks into dependency-safe batches.
 *
 * Checks in the same batch can run together, while later batches wait for their
 * declared dependencies from earlier batches to finish first.
 */
export const getCheckBatches = (checks: Check[]): Check[][] => {
  const checkMap = new Map(checks.map((check) => [check.metadata.id, check]));
  const dag: Record<string, string[]> = {};

  for (const check of checks) {
    dag[check.metadata.id] = [];
  }

  for (const check of checks) {
    const dependencies = check.metadata.dependsOn;
    if (dependencies === undefined) {
      continue;
    }

    for (const dependencyId of dependencies) {
      if (!checkMap.has(dependencyId)) {
        throw new Error(
          `Check '${check.metadata.id}' has unknown dependency '${dependencyId}'`,
        );
      }
      if (!dag[dependencyId]) {
        dag[dependencyId] = [];
      }
      dag[dependencyId].push(check.metadata.id);
    }
  }

  const batches = batchingToposort(dag);
  return batches.map((batch) =>
    batch.map((checkId) => {
      const check = checkMap.get(checkId);
      if (check === undefined) {
        throw new Error(`Check '${checkId}' not found in checkMap`);
      }
      return check;
    }),
  );
};
