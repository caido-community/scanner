import type { SDK } from "caido:plugin";
import type { QueueTask, Result } from "shared";

import {
  clearQueueTasks,
  getQueueTask,
  getQueueTasks,
} from "../services/queue";

export const apiGetQueueTasks = (_sdk: SDK): Result<QueueTask[]> =>
  getQueueTasks();

export const apiGetQueueTask = (
  _sdk: SDK,
  id: string,
): Result<QueueTask | undefined> => getQueueTask(id);

export const apiClearQueueTasks = (_sdk: SDK): Result<void> =>
  clearQueueTasks();
