import type { ScanDefinition, ScanMetadata, ScanType } from "engine";

export type SelectOptions = {
  /**
   * Filter by scan type (e.g. only run PASSIVE checks)
   */
  type?: ScanType;

  /**
   * A whitelist of scan IDs to run. If provided, only these scans are considered
   */
  include?: string[];

  /**
   * A blacklist of scan IDs to skip. This is applied after the 'include' and 'type' filters
   */
  exclude?: string[];

  /**
   * If true, returns ScanMetadata[] instead of ScanDefinition[]
   */
  returnMetadata?: boolean;
};

export class ChecksStore {
  private static _store?: ChecksStore;

  private scans: ScanDefinition[];

  private constructor() {
    this.scans = [];
  }

  static get(): ChecksStore {
    if (!ChecksStore._store) {
      ChecksStore._store = new ChecksStore();
    }

    return ChecksStore._store;
  }

  /**
   * Selects a list of scan metadata based on the provided filtering criteria.
   */
  public select(
    options: SelectOptions & { returnMetadata: true },
  ): ScanMetadata[];

  /**
   * Selects a list of scan definitions based on the provided filtering criteria.
   */
  public select(
    options?: SelectOptions & { returnMetadata?: false | undefined },
  ): ScanDefinition[];

  /**
   * Selects a list of scans based on the provided filtering criteria.
   * Returns either an array of ScanDefinition or ScanMetadata objects based on the options.
   */
  public select(
    options: SelectOptions = {},
  ): ScanDefinition[] | ScanMetadata[] {
    let selectedScans: ScanDefinition[];

    if (options.include) {
      const includeSet = new Set(options.include);
      selectedScans = this.scans.filter((scan) =>
        includeSet.has(scan.metadata.id),
      );
    } else {
      selectedScans = [...this.scans];
    }

    if (options.type) {
      selectedScans = selectedScans.filter(
        (scan) => scan.metadata.type === options.type,
      );
    }

    if (options.exclude) {
      const excludeSet = new Set(options.exclude);
      selectedScans = selectedScans.filter(
        (scan) => !excludeSet.has(scan.metadata.id),
      );
    }

    if (options.returnMetadata === true) {
      return selectedScans.map((scan) => scan.metadata);
    }

    return selectedScans;
  }

  /**
   * Registers a list of scans.
   */
  public register(...scans: ScanDefinition[]) {
    this.scans.push(...scans);
  }

  /**
   * Gets all registered scans without applying any filters.
   */
  public getDefinitions(): ScanDefinition[] {
    return [...this.scans];
  }
}
