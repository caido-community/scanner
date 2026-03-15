import { type QueueTask } from "shared";

export type QueueState =
  | { type: "Idle" }
  | { type: "Loading" }
  | { type: "Error"; error: string }
  | { type: "Success"; tasks: QueueTask[] };

export type QueueSelectionState =
  | { type: "None" }
  | { type: "Loading"; taskId: string }
  | { type: "Error"; taskId: string; error: string }
  | {
      type: "Success";
      taskId: string;
      request: {
        id: string;
        raw: string;
      };
    };
