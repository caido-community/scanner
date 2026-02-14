import type { CheckAggressivity, CheckMetadata } from "engine";
import { computed, ref } from "vue";

import { useChecksService } from "@/services/checks";
import { useConfigService } from "@/services/config";

type AggressivitySortDirection = "none" | "asc" | "desc";

const getAggressivitySortValue = (aggressivity: CheckAggressivity) => {
  if (aggressivity.maxRequests === "Infinity") {
    return Number.POSITIVE_INFINITY;
  }

  return aggressivity.maxRequests;
};

export const useTable = () => {
  const search = ref("");
  const expandedCheckIDs = ref<Array<string>>([]);
  const aggressivitySortDirection = ref<AggressivitySortDirection>("none");

  const checksService = useChecksService();
  const configService = useConfigService();

  const checks = computed(() => {
    const checksState = checksService.getState();
    if (checksState.type !== "Success") return [];

    return checksState.checks;
  });

  const visibleChecks = computed(() => {
    const searchTerm = search.value.trim().toLowerCase();
    const filteredChecks =
      searchTerm === ""
        ? checks.value
        : checks.value.filter((check) => {
            return (
              check.name.toLowerCase().includes(searchTerm) ||
              check.id.toLowerCase().includes(searchTerm) ||
              check.description.toLowerCase().includes(searchTerm)
            );
          });

    if (aggressivitySortDirection.value === "none") {
      return filteredChecks;
    }

    const sortedChecks = [...filteredChecks].sort((a, b) => {
      const difference =
        getAggressivitySortValue(a.aggressivity) -
        getAggressivitySortValue(b.aggressivity);

      if (difference !== 0) {
        return aggressivitySortDirection.value === "asc"
          ? difference
          : -difference;
      }

      return a.name.localeCompare(b.name);
    });

    return sortedChecks;
  });

  const toggleAggressivitySort = () => {
    if (aggressivitySortDirection.value === "none") {
      aggressivitySortDirection.value = "asc";
      return;
    }

    if (aggressivitySortDirection.value === "asc") {
      aggressivitySortDirection.value = "desc";
      return;
    }

    aggressivitySortDirection.value = "none";
  };

  const getAggressivitySortIcon = () => {
    if (aggressivitySortDirection.value === "asc") {
      return "fas fa-sort-up";
    }

    if (aggressivitySortDirection.value === "desc") {
      return "fas fa-sort-down";
    }

    return "fas fa-sort";
  };

  const isExpandedCheck = (checkID: string) => {
    return expandedCheckIDs.value.includes(checkID);
  };

  const toggleExpandedCheck = (checkID: string) => {
    if (isExpandedCheck(checkID)) {
      expandedCheckIDs.value = expandedCheckIDs.value.filter(
        (currentCheckID) => currentCheckID !== checkID,
      );
      return;
    }

    expandedCheckIDs.value = [...expandedCheckIDs.value, checkID];
  };

  const getAggressivityText = (check: CheckMetadata) => {
    const { minRequests, maxRequests } = check.aggressivity;

    if (minRequests === 0 && maxRequests === 0) {
      return "No requests";
    }

    if (minRequests === maxRequests) {
      return `${minRequests} requests`;
    }

    if (maxRequests === "Infinity") {
      return `${minRequests}+ requests`;
    }

    return `${minRequests}–${maxRequests} requests`;
  };

  const getAggressivityBadgeClass = (aggressivity: CheckAggressivity) => {
    const { minRequests, maxRequests } = aggressivity;

    if (minRequests === 0 && maxRequests === 0) {
      return "text-surface-300";
    }

    if (maxRequests === "Infinity") {
      return "text-red-400";
    }

    if (maxRequests >= 10) {
      return "text-amber-300";
    }

    return "text-red-300";
  };

  const getPassiveEnabled = (check: CheckMetadata) => {
    const configState = configService.getState();
    if (configState.type !== "Success") return check.type === "passive";

    const config = configState.config;
    const overrideValue = config.passive.overrides.find(
      (o) => o.checkID === check.id,
    )?.enabled;

    return overrideValue !== undefined
      ? overrideValue
      : check.type === "passive";
  };

  const getActiveEnabled = (check: CheckMetadata) => {
    const configState = configService.getState();
    if (configState.type !== "Success") return true;

    const config = configState.config;
    const overrideValue = config.active.overrides.find(
      (o) => o.checkID === check.id,
    )?.enabled;
    return overrideValue !== undefined ? overrideValue : true;
  };

  const togglePassiveCheck = async (check: CheckMetadata) => {
    const configState = configService.getState();
    if (configState.type !== "Success") return;

    const config = configState.config;
    const currentValue = getPassiveEnabled(check);

    const existingOverrides = config.passive.overrides.filter(
      (o) => o.checkID !== check.id,
    );
    const newOverrides = [
      ...existingOverrides,
      { checkID: check.id, enabled: !currentValue },
    ];

    const update = {
      passive: {
        overrides: newOverrides,
      },
    };

    await configService.updateConfig(update);
  };

  const toggleActiveCheck = async (check: CheckMetadata) => {
    const configState = configService.getState();
    if (configState.type !== "Success") return;

    const config = configState.config;
    const currentValue = getActiveEnabled(check);

    const existingOverrides = config.active.overrides.filter(
      (o) => o.checkID !== check.id,
    );
    const newOverrides = [
      ...existingOverrides,
      { checkID: check.id, enabled: !currentValue },
    ];

    const update = {
      active: {
        overrides: newOverrides,
      },
    };

    await configService.updateConfig(update);
  };

  return {
    search,
    visibleChecks,
    isExpandedCheck,
    toggleExpandedCheck,
    toggleAggressivitySort,
    getAggressivitySortIcon,
    getPassiveEnabled,
    getActiveEnabled,
    getAggressivityText,
    getAggressivityBadgeClass,
    togglePassiveCheck,
    toggleActiveCheck,
  };
};
