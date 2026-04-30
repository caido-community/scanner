import type { QueueTask } from "shared";
import { describe, expect, it, vi } from "vitest";

import { createMockSDK } from "../__tests__/mockSdk";
import { QueueStore } from "../stores/queue";

import { apiClearQueueTasks, apiGetQueueTask, apiGetQueueTasks } from "./queue";

const task: QueueTask = {
  id: "task-1",
  status: "pending",
  request: {
    id: "req-1",
    host: "example.com",
    port: 443,
    path: "/",
    query: "",
    method: "GET",
  },
  executedCheckIDs: [],
  createdAt: 0,
};

describe("apiGetQueueTasks", () => {
  it("returns tasks from the store", () => {
    vi.spyOn(QueueStore, "get").mockReturnValue({
      getTasks: () => [task],
    } as unknown as QueueStore);

    expect(apiGetQueueTasks(createMockSDK() as never)).toEqual({
      kind: "Ok",
      value: [task],
    });
  });
});

describe("apiGetQueueTask", () => {
  it("returns the matching task", () => {
    vi.spyOn(QueueStore, "get").mockReturnValue({
      getTask: () => task,
    } as unknown as QueueStore);

    expect(apiGetQueueTask(createMockSDK() as never, "task-1")).toEqual({
      kind: "Ok",
      value: task,
    });
  });

  it("rejects an invalid id", () => {
    const result = apiGetQueueTask(createMockSDK() as never, "");
    expect(result.kind).toBe("Error");
  });
});

describe("apiClearQueueTasks", () => {
  it("clears the store", () => {
    const clearTasks = vi.fn();
    vi.spyOn(QueueStore, "get").mockReturnValue({
      clearTasks,
    } as unknown as QueueStore);

    expect(apiClearQueueTasks(createMockSDK() as never)).toEqual({
      kind: "Ok",
      value: undefined,
    });
    expect(clearTasks).toHaveBeenCalled();
  });
});
