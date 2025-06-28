import { type SessionState } from "shared";
import { reactive } from "vue";

import { type SessionsSelectionState } from "@/types/scanner";

type Context = {
  state: SessionsSelectionState;
};

type Message =
  | { type: "Reset" }
  | { type: "Start"; sessionId: string }
  | { type: "Error"; sessionId: string; error: string }
  | { type: "Success"; sessionId: string; session: SessionState };

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
  state: SessionsSelectionState & { type: "None" },
  message: Message,
): SessionsSelectionState => {
  switch (message.type) {
    case "Start":
      return {
        type: "Loading",
        sessionId: message.sessionId,
      };
    case "Reset":
    case "Error":
    case "Success":
      return state;
  }
};

const processLoading = (
  state: SessionsSelectionState & { type: "Loading" },
  message: Message,
): SessionsSelectionState => {
  switch (message.type) {
    case "Error":
      return {
        type: "Error",
        sessionId: message.sessionId,
        error: message.error,
      };
    case "Success":
      return {
        type: "Success",
        session: message.session,
      };
    case "Reset":
      return { type: "None" };
    case "Start":
      return state;
  }
};

const processError = (
  state: SessionsSelectionState & { type: "Error" },
  message: Message,
): SessionsSelectionState => {
  switch (message.type) {
    case "Start":
      return {
        type: "Loading",
        sessionId: message.sessionId,
      };
    case "Reset":
      return { type: "None" };
    case "Error":
    case "Success":
      return state;
  }
};

const processSuccess = (
  state: SessionsSelectionState & { type: "Success" },
  message: Message,
): SessionsSelectionState => {
  switch (message.type) {
    case "Start":
      return {
        type: "Loading",
        sessionId: message.sessionId,
      };
    case "Reset":
      return { type: "None" };
    case "Error":
    case "Success":
      return state;
  }
};
