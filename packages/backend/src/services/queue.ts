import { type QueueTask, Result } from "shared";

import { IdSchema } from "../schemas";
import { QueueStore } from "../stores/queue";
import { validateInput } from "../utils/validation";

export const getQueueTasks = (): Result<QueueTask[]> => {
  const store = QueueStore.get();
  return Result.ok(store.getTasks());
};

export const getQueueTask = (id: string): Result<QueueTask | undefined> => {
  const validation = validateInput(IdSchema, id);
  if (validation.kind === "Error") {
    return validation;
  }

  const store = QueueStore.get();
  return Result.ok(store.getTask(validation.value));
};

export const clearQueueTasks = (): Result<void> => {
  const store = QueueStore.get();
  store.clearTasks();
  return Result.ok(undefined);
};
