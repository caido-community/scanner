import type { Severity } from "engine";
import type { DataTableFilterMeta } from "primevue/datatable";
import type { SessionState } from "shared";
import { computed, type Ref } from "vue";

export const useTable = (options: {
  search: Ref<string>;
  statusFilter: Ref<string>;
}) => {
  const { search, statusFilter } = options;
  const filters = computed<DataTableFilterMeta>(() => ({
    global: { value: search.value, matchMode: "contains" },
  }));

  const getFilteredSessions = (sessions: SessionState[]) => {
    return sessions.filter((session) => {
      const statusMatches = filterByStatus(session.kind, statusFilter.value);
      return statusMatches;
    });
  };

  const filterByStatus = (value: string, filter: string) => {
    if (!filter || filter === "all") return true;

    if (filter === "running") {
      return value === "Running" || value === "Pending";
    }

    if (filter === "finished") {
      return value === "Done" || value === "Interrupted" || value === "Error";
    }

    return true;
  };

  const getStatusSeverity = (status: string) => {
    switch (status) {
      case "Running":
        return "info";
      case "Done":
        return "success";
      case "Error":
        return "danger";
      case "Interrupted":
        return "warn";
      default:
        return "secondary";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "Running":
        return "fas fa-spinner fa-spin";
      case "Done":
        return "fas fa-check";
      case "Error":
        return "fas fa-times";
      case "Interrupted":
        return "fas fa-pause";
      default:
        return "fas fa-question";
    }
  };

  const getRequestsCount = (data: SessionState) => {
    return data.kind === "Running" || data.kind === "Done"
      ? data.progress.requestsSent
      : 0;
  };

  const getSeverityColor = (severity: Severity): string => {
    switch (severity) {
      case "critical":
      case "high":
        return "danger";
      case "medium":
        return "warn";
      case "low":
        return "info";
      case "info":
        return "secondary";
      default:
        return "secondary";
    }
  };

  const getSeverityBadgeData = (data: SessionState) => {
    const hasFindings =
      data.kind === "Running" ||
      data.kind === "Done" ||
      data.kind === "Interrupted";
    if (!hasFindings) return [];

    const severityCounts = data.findings.reduce(
      (acc, finding) => {
        acc[finding.severity] = (acc[finding.severity] || 0) + 1;
        return acc;
      },
      {} as Record<Severity, number>,
    );

    const severityOrder: Severity[] = [
      "critical",
      "high",
      "medium",
      "low",
      "info",
    ];

    return severityOrder
      .filter((severity) => severityCounts[severity] > 0)
      .map((severity) => ({
        severity,
        count: severityCounts[severity],
        color: getSeverityColor(severity),
      }));
  };

  return {
    filters,
    getFilteredSessions,
    filterByStatus,
    getStatusSeverity,
    getStatusIcon,
    getRequestsCount,
    getSeverityBadgeData,
  };
};
