import { reactive } from "vue";

import { type QueueSelectionState } from "@/types/queue";

type Context = {
  state: QueueSelectionState;
};

type Message =
  | { type: "Reset" }
  | { type: "Start"; taskId: string }
  | { type: "Error"; taskId: string; error: string }
  | {
      type: "Success";
      taskId: string;
      request: { id: string; raw: string };
    };

export const useSelectionState = () => {
  const context: Context = reactive({
    state: { type: "None" },
  });

  const getState = () => context.state;

  const send = (message: Message) => {
    const currState = context.state;

    switch (currState.type) {
      case "None":
        context.state = processNone(currState, message);
        break;
      case "Loading":
        context.state = processLoading(currState, message);
        break;
      case "Error":
        context.state = processError(currState, message);
        break;
      case "Success":
        context.state = processSuccess(currState, message);
        break;
    }
  };

  return {
    selectionState: {
      getState,
      send,
    },
  };
};

const processNone = (
  state: QueueSelectionState & { type: "None" },
  message: Message,
): QueueSelectionState => {
  switch (message.type) {
    case "Start":
      return {
        type: "Loading",
        taskId: message.taskId,
      };
    case "Reset":
    case "Error":
    case "Success":
      return state;
  }
};

const processLoading = (
  state: QueueSelectionState & { type: "Loading" },
  message: Message,
): QueueSelectionState => {
  switch (message.type) {
    case "Error":
      return {
        type: "Error",
        taskId: message.taskId,
        error: message.error,
      };
    case "Success":
      return {
        type: "Success",
        taskId: message.taskId,
        request: message.request,
      };
    case "Reset":
      return { type: "None" };
    case "Start":
      return state;
  }
};

const processError = (
  state: QueueSelectionState & { type: "Error" },
  message: Message,
): QueueSelectionState => {
  switch (message.type) {
    case "Start":
      return {
        type: "Loading",
        taskId: message.taskId,
      };
    case "Reset":
      return { type: "None" };
    case "Error":
    case "Success":
      return state;
  }
};

const processSuccess = (
  state: QueueSelectionState & { type: "Success" },
  message: Message,
): QueueSelectionState => {
  switch (message.type) {
    case "Start":
      return {
        type: "Loading",
        taskId: message.taskId,
      };
    case "Reset":
      return { type: "None" };
    case "Error":
    case "Success":
      return state;
  }
};
