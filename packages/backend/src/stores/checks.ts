import type { CheckDefinition, CheckMetadata } from "engine";
import type { SelectOptions } from "shared";

export class ChecksStore {
  private static _store?: ChecksStore;

  private checks: CheckDefinition[];

  private constructor() {
    this.checks = [];
  }

  static get(): ChecksStore {
    if (!ChecksStore._store) {
      ChecksStore._store = new ChecksStore();
    }

    return ChecksStore._store;
  }

  /**
   * Selects a list of check metadata based on the provided filtering criteria.
   */
  public select(
    options: SelectOptions & { returnMetadata: true },
  ): CheckMetadata[];

  /**
   * Selects a list of check definitions based on the provided filtering criteria.
   */
  public select(
    options?: SelectOptions & { returnMetadata?: false | undefined },
  ): CheckDefinition[];

  /**
   * Selects a list of checks based on the provided filtering criteria.
   * Returns either an array of CheckDefinition or CheckMetadata objects based on the options.
   */
  public select(
    options: SelectOptions = {},
  ): CheckDefinition[] | CheckMetadata[] {
    let selectedChecks: CheckDefinition[];

    if (options.include) {
      const includeSet = new Set(options.include);
      selectedChecks = this.checks.filter((check) =>
        includeSet.has(check.metadata.id),
      );
    } else {
      selectedChecks = [...this.checks];
    }

    if (options.type) {
      const overrides = options.overrides ?? {};
      selectedChecks = selectedChecks.filter((check) => {
        const override = overrides[check.metadata.id];
        if (override === true) {
          return true;
        }

        if (override === false) {
          return false;
        }

        return check.metadata.type === options.type;
      });
    }

    if (options.exclude) {
      const excludeSet = new Set(options.exclude);
      selectedChecks = selectedChecks.filter(
        (check) => !excludeSet.has(check.metadata.id),
      );
    }

    if (options.returnMetadata === true) {
      return selectedChecks.map((check) => check.metadata);
    }

    return selectedChecks;
  }

  /**
   * Registers a list of checks.
   */
  public register(...checks: CheckDefinition[]) {
    this.checks.push(...checks);
  }

  /**
   * Gets all registered checks without applying any filters.
   */
  public getDefinitions(): CheckDefinition[] {
    return [...this.checks];
  }
}
