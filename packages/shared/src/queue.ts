import type { BasicRequest } from "./request";

type QueueTaskBase = {
  id: string;
  request: BasicRequest;
  executedCheckIDs: string[];
  createdAt: number;
};

export type QueueTask =
  | (QueueTaskBase & {
      status: "pending";
    })
  | (QueueTaskBase & {
      status: "running";
      startedAt: number;
    })
  | (QueueTaskBase & {
      status: "completed";
      startedAt: number;
      finishedAt: number;
    })
  | (QueueTaskBase & {
      status: "failed";
      finishedAt: number;
      error: string;
      startedAt?: number;
    })
  | (QueueTaskBase & {
      status: "cancelled";
      finishedAt: number;
      error: string;
      startedAt?: number;
    });
