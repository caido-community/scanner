import { Result } from "engine";
import type { QueueTask, Result as ResultType } from "shared";

import { IdSchema } from "../schemas";
import { QueueStore } from "../stores/queue";
import { type BackendSDK } from "../types";
import { validateInput } from "../utils/validation";

export const getQueueTasks = (_: BackendSDK): ResultType<QueueTask[]> => {
  const store = QueueStore.get();
  return Result.ok(store.getTasks());
};

export const getQueueTask = (
  _: BackendSDK,
  id: string,
): ResultType<QueueTask | undefined> => {
  const validation = validateInput(IdSchema, id);
  if (validation.kind === "Error") {
    return validation;
  }

  const store = QueueStore.get();
  return Result.ok(store.getTask(validation.value));
};

export const clearQueueTasks = (_: BackendSDK): ResultType<void> => {
  const store = QueueStore.get();
  store.clearTasks();
  return Result.ok(undefined);
};
