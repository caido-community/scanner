import { useTimestamp } from "@vueuse/core";
import { Severity } from "engine";
import { type Session } from "shared";
import { computed, type Ref, ref, watch } from "vue";

import {
  createSessionFindings,
  type RequestPreviewState,
} from "./utils";

import { useScannerRepository } from "@/repositories/scanner";
import { useScannerService } from "@/services/scanner";

export const useForm = (session: Ref<Session>) => {
  const now = useTimestamp({ interval: 50 });

  const { cancelScanSession, deleteScanSession, rerunScanSession } =
    useScannerService();
  const { getRequestResponse } = useScannerRepository();
  const isDeleting = ref(false);
  const isCancelling = ref(false);
  const isRerunning = ref(false);
  const showDeleteDialog = ref(false);
  const showRerunDialog = ref(false);
  const activeView = ref<"summary" | "findings">("summary");
  const selectedFindingId = ref<string | undefined>(undefined);
  const requestStates = ref<Record<string, RequestPreviewState>>({});

  const getStatusColor = (kind: string) => {
    switch (kind) {
      case "Running":
        return "bg-yellow-500";
      case "Done":
        return "bg-success-500";
      case "Error":
        return "bg-red-500";
      case "Interrupted":
        return "bg-orange-500";
      default:
        return "bg-surface-400";
    }
  };

  const progress = computed(() => {
    if (
      session.value.kind === "Running" ||
      session.value.kind === "Done" ||
      session.value.kind === "Interrupted"
    ) {
      const checksCompleted = session.value.progress.checksHistory.filter(
        (check) => check.kind === "Completed",
      ).length;
      const checksFailed = session.value.progress.checksHistory.filter(
        (check) => check.kind === "Failed",
      ).length;
      const checksFinished = checksCompleted + checksFailed;
      const { checksTotal } = session.value.progress;
      if (checksTotal === 0) return 0;
      return Math.round((checksFinished / checksTotal) * 100);
    }
    return 0;
  });

  const requestsSent = computed(() => {
    if (
      session.value.kind === "Running" ||
      session.value.kind === "Done" ||
      session.value.kind === "Interrupted"
    ) {
      return session.value.progress.checksHistory.reduce((total, check) => {
        return total + check.requestsSent.length;
      }, 0);
    }
    return 0;
  });

  const requestsPending = computed(() => {
    if (
      session.value.kind === "Running" ||
      session.value.kind === "Done" ||
      session.value.kind === "Interrupted"
    ) {
      return session.value.progress.checksHistory.reduce((total, check) => {
        return (
          total +
          check.requestsSent.filter((req) => req.status === "pending").length
        );
      }, 0);
    }
    return 0;
  });

  const requestsFailed = computed(() => {
    if (
      session.value.kind === "Running" ||
      session.value.kind === "Done" ||
      session.value.kind === "Interrupted"
    ) {
      return session.value.progress.checksHistory.reduce((total, check) => {
        return (
          total +
          check.requestsSent.filter((req) => req.status === "failed").length
        );
      }, 0);
    }
    return 0;
  });

  const checksCompleted = computed(() => {
    if (
      session.value.kind === "Running" ||
      session.value.kind === "Done" ||
      session.value.kind === "Interrupted"
    ) {
      return session.value.progress.checksHistory.filter(
        (check) => check.kind === "Completed",
      ).length;
    }
    return 0;
  });

  const checksFailed = computed(() => {
    if (
      session.value.kind === "Running" ||
      session.value.kind === "Done" ||
      session.value.kind === "Interrupted"
    ) {
      return session.value.progress.checksHistory.filter(
        (check) => check.kind === "Failed",
      ).length;
    }
    return 0;
  });

  const checksRunning = computed(() => {
    if (
      session.value.kind === "Running" ||
      session.value.kind === "Done" ||
      session.value.kind === "Interrupted"
    ) {
      return session.value.progress.checksHistory.filter(
        (check) => check.kind === "Running",
      );
    }
    return [];
  });

  const severityOrder = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
  ];
  const severityRank = new Map(
    severityOrder.map((severity, index) => [severity, index]),
  );

  const getPreciseTimeAgo = (date: Date) => {
    const diff = Math.floor((now.value - date.getTime()) / 1000);
    if (diff < 60) return `${diff} seconds ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)} minutes ago`;
    return `${Math.floor(diff / 3600)} hours ago`;
  };

  const timeSinceCreated = computed(() =>
    getPreciseTimeAgo(new Date(session.value.createdAt)),
  );

  const timeSinceFinished = computed(() => {
    if (session.value.kind === "Done") {
      return getPreciseTimeAgo(new Date(session.value.finishedAt));
    }

    return "Invalid State";
  });

  const onCancel = async () => {
    isCancelling.value = true;
    await cancelScanSession(session.value.id);
    isCancelling.value = false;
  };

  const onDelete = () => {
    showDeleteDialog.value = true;
  };

  const onConfirmDelete = () => {
    isDeleting.value = true;
    deleteScanSession(session.value.id);
    isDeleting.value = false;
    showDeleteDialog.value = false;
  };

  const onCancelDelete = () => {
    showDeleteDialog.value = false;
  };

  const onRerun = () => {
    showRerunDialog.value = true;
  };

  const onConfirmRerun = async () => {
    isRerunning.value = true;
    await rerunScanSession(session.value.id);
    isRerunning.value = false;
    showRerunDialog.value = false;
  };

  const onCancelRerun = () => {
    showRerunDialog.value = false;
  };

  const findings = computed(() => {
    if (
      session.value.kind !== "Running" &&
      session.value.kind !== "Done" &&
      session.value.kind !== "Interrupted"
    ) {
      return [];
    }

    return session.value.progress.checksHistory.flatMap(
      (check) => check.findings,
    );
  });

  const sessionFindings = computed(() => {
    return [...createSessionFindings(session.value)].sort((left, right) => {
      const leftRank = severityRank.get(left.severity) ?? severityOrder.length;
      const rightRank =
        severityRank.get(right.severity) ?? severityOrder.length;

      if (leftRank !== rightRank) {
        return leftRank - rightRank;
      }

      return left.name.localeCompare(right.name);
    });
  });

  const hasFindings = computed(() => sessionFindings.value.length > 0);

  const selectedFinding = computed(() => {
    if (selectedFindingId.value === undefined) {
      return sessionFindings.value[0];
    }

    return sessionFindings.value.find(
      (finding) => finding.id === selectedFindingId.value,
    );
  });

  const getRequestState = (requestId: string): RequestPreviewState => {
    return requestStates.value[requestId] ?? { type: "Idle" };
  };

  const loadRequest = async (requestId: string, force = false) => {
    const existingState = requestStates.value[requestId];
    if (
      force === false &&
      (existingState?.type === "Loading" || existingState?.type === "Success")
    ) {
      return;
    }

    requestStates.value = {
      ...requestStates.value,
      [requestId]: { type: "Loading" },
    };

    const currentSessionId = session.value.id;
    const result = await getRequestResponse(requestId);
    if (session.value.id !== currentSessionId) {
      return;
    }

    if (result.kind === "Ok") {
      requestStates.value = {
        ...requestStates.value,
        [requestId]: {
          type: "Success",
          request: result.value.request,
          response: result.value.response,
        },
      };
      return;
    }

    requestStates.value = {
      ...requestStates.value,
      [requestId]: { type: "Error", error: result.error },
    };
  };

  const openFindings = () => {
    activeView.value = "findings";
  };

  const backToSummary = () => {
    activeView.value = "summary";
  };

  const selectFinding = (findingId: string) => {
    selectedFindingId.value = findingId;
  };

  const retryRequest = (requestId: string) => {
    void loadRequest(requestId, true);
  };

  watch(
    () => session.value.id,
    () => {
      activeView.value = "summary";
      selectedFindingId.value = undefined;
      requestStates.value = {};
    },
  );

  watch(
    sessionFindings,
    (nextFindings) => {
      const selectedId = selectedFindingId.value;
      if (selectedId === undefined) {
        selectedFindingId.value = nextFindings[0]?.id;
        return;
      }

      const selectionStillExists = nextFindings.some(
        (finding) => finding.id === selectedId,
      );
      if (selectionStillExists === false) {
        selectedFindingId.value = nextFindings[0]?.id;
      }
    },
    { immediate: true },
  );

  watch(
    [activeView, sessionFindings],
    ([view, nextFindings]) => {
      if (view !== "findings") {
        return;
      }

      const requestIds = new Set(
        nextFindings.map((finding) => finding.findingRequestID),
      );

      for (const requestId of requestIds) {
        void loadRequest(requestId);
      }
    },
    { immediate: true },
  );

  watch(
    selectedFinding,
    (finding) => {
      if (finding === undefined) {
        return;
      }

      void loadRequest(finding.findingRequestID);
    },
    { immediate: true },
  );

  const selectedFindingRequestState = computed(() => {
    const finding = selectedFinding.value;
    if (finding === undefined) {
      return { type: "Idle" } satisfies RequestPreviewState;
    }

    return getRequestState(finding.findingRequestID);
  });

  return {
    getStatusColor,
    severityOrder,
    progress,
    requestsSent,
    requestsPending,
    requestsFailed,
    checksCompleted,
    checksFailed,
    checksRunning,
    timeSinceCreated,
    timeSinceFinished,
    onCancel,
    onDelete,
    onRerun,
    onConfirmDelete,
    onCancelDelete,
    onConfirmRerun,
    onCancelRerun,
    isDeleting,
    isCancelling,
    isRerunning,
    showDeleteDialog,
    showRerunDialog,
    findings,
    activeView,
    openFindings,
    backToSummary,
    hasFindings,
    sessionFindings,
    selectedFinding,
    selectedFindingId,
    selectFinding,
    getRequestState,
    selectedFindingRequestState,
    retryRequest,
  };
};
