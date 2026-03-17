import type { ScanRunnable } from "engine";
import type { BasicRequest, QueueTask } from "shared";

import {
  addExecutedCheck,
  createQueueTask,
  pruneQueueTasks,
  updateQueueTask,
} from "./queue.utils";

type PassiveTaskQueue = {
  clearPending: (reason: string) => void;
  setConcurrency: (concurrency: number) => void;
};

export class QueueStore {
  private static instance?: QueueStore;

  private tasks: QueueTask[];
  private cancelFunctions: Map<string, () => void>;
  private passiveTaskQueue?: PassiveTaskQueue;

  private constructor() {
    this.tasks = [];
    this.cancelFunctions = new Map();
  }

  static get(): QueueStore {
    if (!QueueStore.instance) {
      QueueStore.instance = new QueueStore();
    }

    return QueueStore.instance;
  }

  setPassiveTaskQueue(queue: PassiveTaskQueue): void {
    this.passiveTaskQueue = queue;
  }

  switchProject(_: string | undefined): void {
    this.tasks = [];
    this.cancelFunctions.clear();
  }

  addTask(id: string, request: BasicRequest): QueueTask {
    const task = createQueueTask({
      id,
      request,
      now: Date.now(),
    });

    this.tasks = pruneQueueTasks({
      tasks: [...this.tasks, task],
      maxTasks: 100,
    });
    return task;
  }

  addActiveRunnable(id: string, runnable: ScanRunnable): void {
    this.cancelFunctions.set(id, () => runnable.cancel("Cancelled"));
  }

  removeActiveRunnable(id: string): void {
    this.cancelFunctions.delete(id);
  }

  addExecutedCheck(id: string, checkID: string): QueueTask | undefined {
    const index = this.tasks.findIndex((task) => task.id === id);
    if (index === -1) {
      return undefined;
    }

    const task = this.tasks[index];
    if (task === undefined) {
      return undefined;
    }

    const nextTask = addExecutedCheck({
      task,
      checkID,
    });
    this.tasks[index] = nextTask;
    return nextTask;
  }

  updateTaskStatus(
    id: string,
    status: QueueTask["status"],
    error?: string,
  ): QueueTask | undefined {
    const index = this.tasks.findIndex((task) => task.id === id);
    if (index !== -1) {
      const task = this.tasks[index];
      if (task !== undefined) {
        const nextTask = updateQueueTask({
          task,
          status,
          now: Date.now(),
          error,
        });
        this.tasks[index] = nextTask;
        this.tasks = pruneQueueTasks({
          tasks: this.tasks,
          maxTasks: 100,
        });
        return nextTask;
      }
    }

    return undefined;
  }

  getTasks(): QueueTask[] {
    return [...this.tasks];
  }

  getTask(id: string): QueueTask | undefined {
    return this.tasks.find((t) => t.id === id);
  }

  clearTasks(): void {
    for (const cancelFunction of this.cancelFunctions.values()) {
      cancelFunction();
    }
    this.cancelFunctions.clear();

    this.passiveTaskQueue?.clearPending("Cancelled");
    this.tasks = [];
  }
}
