import { describe, expect, it } from "vitest";

import {
  addExecutedCheck,
  createQueueTask,
  pruneQueueTasks,
  updateQueueTask,
} from "./queue.utils";

const request = {
  id: "req-1",
  host: "example.com",
  port: 443,
  path: "/search",
  query: "q=test",
  method: "GET",
} as const;

describe("queue utils", () => {
  it("creates pending tasks with request summaries and empty check lists", () => {
    expect(
      createQueueTask({
        id: "task-1",
        request,
        now: 10,
      }),
    ).toEqual({
      id: "task-1",
      request,
      executedCheckIDs: [],
      status: "pending",
      createdAt: 10,
    });
  });

  it("updates terminal statuses with finishedAt", () => {
    const task = createQueueTask({
      id: "task-1",
      request,
      now: 10,
    });

    expect(
      updateQueueTask({
        task,
        status: "running",
        now: 20,
      }),
    ).toEqual({
      ...task,
      status: "running",
      startedAt: 20,
    });

    expect(
      updateQueueTask({
        task,
        status: "failed",
        now: 30,
        error: "boom",
      }),
    ).toEqual({
      ...task,
      status: "failed",
      finishedAt: 30,
      error: "boom",
    });
  });

  it("creates startedAt when completing a task directly", () => {
    const task = createQueueTask({
      id: "task-1",
      request,
      now: 10,
    });

    expect(
      updateQueueTask({
        task,
        status: "completed",
        now: 20,
      }),
    ).toEqual({
      ...task,
      status: "completed",
      startedAt: 20,
      finishedAt: 20,
    });
  });

  it("adds executed checks once and keeps them across status transitions", () => {
    const task = createQueueTask({
      id: "task-1",
      request,
      now: 10,
    });

    const withStartedChecks = addExecutedCheck({
      task: addExecutedCheck({
        task,
        checkID: "application-errors",
      }),
      checkID: "application-errors",
    });

    expect(withStartedChecks.executedCheckIDs).toEqual(["application-errors"]);

    expect(
      updateQueueTask({
        task: withStartedChecks,
        status: "completed",
        now: 20,
      }).executedCheckIDs,
    ).toEqual(["application-errors"]);
  });

  it("prunes oldest terminal tasks first", () => {
    const tasks = [
      {
        ...createQueueTask({
          id: "1",
          request: { ...request, id: "r1" },
          now: 1,
        }),
        status: "completed" as const,
        startedAt: 2,
        finishedAt: 2,
      },
      {
        ...createQueueTask({
          id: "2",
          request: { ...request, id: "r2" },
          now: 2,
        }),
        status: "completed" as const,
        startedAt: 3,
        finishedAt: 3,
      },
      {
        ...createQueueTask({
          id: "3",
          request: { ...request, id: "r3" },
          now: 3,
        }),
        status: "running" as const,
        startedAt: 4,
      },
      {
        ...createQueueTask({
          id: "4",
          request: { ...request, id: "r4" },
          now: 4,
        }),
        status: "pending" as const,
      },
    ];

    expect(
      pruneQueueTasks({
        tasks,
        maxTasks: 3,
      }).map((task) => task.id),
    ).toEqual(["3", "4", "2"]);
  });
});
