import { defineStore } from "pinia";

import { useSDK } from "@/plugins/sdk";
import { useQueueRepository } from "@/repositories/queue";
import { useQueueStore } from "@/stores/queue";

export const useQueueService = defineStore("services.queue", () => {
  const sdk = useSDK();
  const store = useQueueStore();
  const repository = useQueueRepository();

  const getState = () => store.getState();

  const initialize = async () => {
    store.send({ type: "Start" });

    const result = await sdk.backend.getQueueTasks();
    if (result.kind === "Ok") {
      store.send({ type: "Success", tasks: result.value });
    } else {
      store.send({ type: "Error", error: result.error });
      sdk.window.showToast("Failed to load queue tasks", {
        variant: "error",
      });
    }

    // TODO: currently turned off because of performance issues
    // sdk.backend.onEvent("passive:queue-new", (taskId, requestID) => {
    //   store.send({ type: "AddTask", taskId, requestID });
    // });

    // sdk.backend.onEvent("passive:queue-started", (taskId) => {
    //   store.send({ type: "StartTask", taskId });
    // });

    // sdk.backend.onEvent("passive:queue-finished", (taskId) => {
    //   store.send({ type: "FinishTask", taskId });
    // });
  };

  const clearQueue = async () => {
    const result = await repository.clearQueueTasks();
    if (result.kind === "Ok") {
      store.send({ type: "Clear" });
    } else {
      store.send({ type: "Error", error: result.error });
      sdk.window.showToast("Failed to clear queue", {
        variant: "error",
      });
    }
  };

  return {
    getState,
    initialize,
    clearQueue,
  };
});
