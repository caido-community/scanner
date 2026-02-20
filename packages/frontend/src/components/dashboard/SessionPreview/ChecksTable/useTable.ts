import { type Session } from "shared";
import { computed, type Ref } from "vue";

export const useTable = (session: Ref<Session>) => {
  const checksHistory = computed(() => {
    if (
      session.value.kind !== "Running" &&
      session.value.kind !== "Done" &&
      session.value.kind !== "Interrupted"
    ) {
      return [];
    }

    return session.value.progress.checksHistory.map((check) => {
      return {
        id: check.id,
        name: check.checkID,
        status: check.kind,
        targetID: check.targetRequestID,
        requestsSent: check.requestsSent.length,
        findings: check.findings,
      };
    });
  });

  return {
    checksHistory,
  };
};
