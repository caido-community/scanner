import { type CheckMetadata } from "engine";
import { defineStore } from "pinia";
import { reactive } from "vue";

import { type ChecksState } from "@/types/checks";

type Context = {
  state: ChecksState;
};

type Message =
  | { type: "Start" }
  | { type: "Error"; error: string }
  | { type: "Success"; checks: CheckMetadata[] };

export const useChecksStore = defineStore("stores.checks", () => {
  const context: Context = reactive({
    state: { type: "Idle" },
  });

  const getState = () => context.state;

  const send = (message: Message) => {
    const currState = context.state;

    switch (currState.type) {
      case "Idle":
        context.state = processIdle(currState, message);
        break;
      case "Error":
        context.state = processError(currState, message);
        break;
      case "Success":
        context.state = processSuccess(currState, message);
        break;
      case "Loading":
        context.state = processLoading(currState, message);
        break;
    }
  };

  return { getState, send };
});

const processIdle = (
  state: ChecksState & { type: "Idle" },
  message: Message,
): ChecksState => {
  switch (message.type) {
    case "Start":
      return { type: "Loading" };
    case "Error":
    case "Success":
      return state;
  }
};

const processError = (
  state: ChecksState & { type: "Error" },
  message: Message,
): ChecksState => {
  switch (message.type) {
    case "Start":
      return { type: "Loading" };
    case "Error":
    case "Success":
      return state;
  }
};

const processSuccess = (
  state: ChecksState & { type: "Success" },
  message: Message,
): ChecksState => {
  switch (message.type) {
    case "Start":
    case "Error":
    case "Success":
      return state;
  }
};

const processLoading = (
  state: ChecksState & { type: "Loading" },
  message: Message,
): ChecksState => {
  switch (message.type) {
    case "Error":
      return { type: "Error", error: message.error };
    case "Success":
      return { type: "Success", checks: message.checks };
    case "Start":
      return state;
  }
};
