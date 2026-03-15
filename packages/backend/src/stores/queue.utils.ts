import type { BasicRequest, QueueTask } from "shared";

export const createQueueTask = ({
  id,
  request,
  now,
}: {
  id: string;
  request: BasicRequest;
  now: number;
}): QueueTask => ({
  id,
  request,
  executedCheckIDs: [],
  status: "pending",
  createdAt: now,
});

export const addExecutedCheck = ({
  task,
  checkID,
}: {
  task: QueueTask;
  checkID: string;
}): QueueTask => {
  if (task.executedCheckIDs.includes(checkID)) {
    return task;
  }

  return {
    ...task,
    executedCheckIDs: [...task.executedCheckIDs, checkID],
  };
};

export const updateQueueTask = ({
  task,
  status,
  now,
  error,
}: {
  task: QueueTask;
  status: QueueTask["status"];
  now: number;
  error?: string;
}): QueueTask => {
  if (status === "running") {
    const startedAt =
      task.status === "running" || task.status === "completed"
        ? task.startedAt
        : now;

    return {
      ...task,
      status,
      startedAt,
    };
  }

  if (status === "completed") {
    const startedAt =
      task.status === "running" || task.status === "completed"
        ? task.startedAt
        : now;

    return {
      ...task,
      status,
      startedAt,
      finishedAt: now,
    };
  }

  if (status === "failed" || status === "cancelled") {
    return {
      ...task,
      status,
      finishedAt: now,
      error: error ?? status,
      ...(task.status === "running" || task.status === "completed"
        ? { startedAt: task.startedAt }
        : {}),
    };
  }

  return task;
};

export const pruneQueueTasks = ({
  tasks,
  maxTasks,
}: {
  tasks: QueueTask[];
  maxTasks: number;
}): QueueTask[] => {
  if (tasks.length <= maxTasks) {
    return tasks;
  }

  const activeTasks = tasks.filter(
    (task) => task.status === "pending" || task.status === "running",
  );
  const terminalTasks = tasks
    .filter((task) => task.status !== "pending" && task.status !== "running")
    .slice(-(maxTasks - activeTasks.length));

  return [...activeTasks, ...terminalTasks];
};
