import { defineStore } from "pinia";
import { type QueueTask } from "shared";
import { ref } from "vue";

import { useSDK } from "@/plugins/sdk";
import { useQueueRepository } from "@/repositories/queue";
import { useQueueStore } from "@/stores/queue";

export const useQueueService = defineStore("services.queue", () => {
  const sdk = useSDK();
  const store = useQueueStore();
  const repository = useQueueRepository();
  const initialized = ref(false);
  const queueListener = ref<{ stop: () => void } | undefined>(undefined);

  const getState = () => store.getState();
  const getSelectionState = () => store.selectionState.getState();

  const resetSelectionIfMissing = (tasks: QueueTask[]) => {
    const selection = store.selectionState.getState();
    if (selection.type === "None") {
      return;
    }

    const selectedTaskExists = tasks.some(
      (task) => task.id === selection.taskId,
    );
    if (!selectedTaskExists) {
      store.selectionState.send({ type: "Reset" });
    }
  };

  const stopQueueUpdates = () => {
    queueListener.value?.stop();
    queueListener.value = undefined;
  };

  const loadQueueTasks = async () => {
    const result = await repository.getQueueTasks();
    if (result.kind === "Ok") {
      resetSelectionIfMissing(result.value);
      store.send({ type: "Success", tasks: result.value });
      return;
    }

    store.send({ type: "Error", error: result.error });
    sdk.window.showToast("Failed to load queue tasks", {
      variant: "error",
    });
  };

  const initialize = async () => {
    if (initialized.value) {
      return;
    }

    initialized.value = true;
    store.send({ type: "Start" });
    stopQueueUpdates();
    queueListener.value = sdk.backend.onEvent(
      "passive:queue-updated",
      (tasks) => {
        resetSelectionIfMissing(tasks);
        store.send({ type: "Success", tasks });
      },
    );

    await loadQueueTasks();
  };

  const dispose = () => {
    stopQueueUpdates();
    initialized.value = false;
  };

  const clearQueue = async () => {
    const result = await repository.clearQueueTasks();
    if (result.kind === "Ok") {
      store.selectionState.send({ type: "Reset" });
      store.send({ type: "Clear" });
    } else {
      store.send({ type: "Error", error: result.error });
      sdk.window.showToast("Failed to clear queue", {
        variant: "error",
      });
    }
  };

  const clearSelection = () => {
    store.selectionState.send({ type: "Reset" });
  };

  const selectTask = async (task: QueueTask) => {
    const currentSelection = store.selectionState.getState();
    if (
      currentSelection.type !== "None" &&
      currentSelection.taskId === task.id
    ) {
      clearSelection();
      return;
    }

    store.selectionState.send({ type: "Start", taskId: task.id });

    const result = await repository.getRequestResponse(task.request.id);
    const latestSelection = store.selectionState.getState();
    if (latestSelection.type === "None" || latestSelection.taskId !== task.id) {
      return;
    }

    if (result.kind === "Ok") {
      store.selectionState.send({
        type: "Success",
        taskId: task.id,
        request: result.value.request,
      });
      return;
    }

    store.selectionState.send({
      type: "Error",
      taskId: task.id,
      error: result.error,
    });
  };

  return {
    getState,
    getSelectionState,
    initialize,
    dispose,
    clearQueue,
    clearSelection,
    selectTask,
  };
});
