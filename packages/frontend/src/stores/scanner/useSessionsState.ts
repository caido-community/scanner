import { type SessionState } from "shared";
import { reactive } from "vue";

import { type SessionsState } from "@/types/scanner";

type Context = {
  state: SessionsState;
};

type Message =
  | { type: "Start" }
  | { type: "Error"; error: string }
  | { type: "Success"; sessions: SessionState[] }
  | { type: "AddSession"; session: SessionState }
  | { type: "UpdateSession"; session: SessionState }
  | { type: "Clear" };

export const useSessionsState = () => {
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
};

const processIdle = (
  state: SessionsState & { type: "Idle" },
  message: Message,
): SessionsState => {
  switch (message.type) {
    case "Start":
      return { type: "Loading" };
    case "Error":
    case "Success":
    case "AddSession":
    case "UpdateSession":
    case "Clear":
      return state;
  }
};

const processError = (
  state: SessionsState & { type: "Error" },
  message: Message,
): SessionsState => {
  switch (message.type) {
    case "Start":
      return { type: "Loading" };
    case "Clear":
      return { type: "Idle" };
    case "Error":
    case "Success":
    case "AddSession":
    case "UpdateSession":
      return state;
  }
};

const processSuccess = (
  state: SessionsState & { type: "Success" },
  message: Message,
): SessionsState => {
  switch (message.type) {
    case "AddSession":
      return {
        ...state,
        sessions: [...state.sessions, message.session],
      };
    case "UpdateSession":
      return {
        ...state,
        sessions: state.sessions.map((session) =>
          session.id === message.session.id ? message.session : session,
        ),
      };
    case "Clear":
      return { type: "Idle" };
    case "Start":
    case "Error":
    case "Success":
      return state;
  }
};

const processLoading = (
  state: SessionsState & { type: "Loading" },
  message: Message,
): SessionsState => {
  switch (message.type) {
    case "Error":
      return { type: "Error", error: message.error };
    case "Success":
      return { type: "Success", sessions: message.sessions };
    case "Start":
    case "AddSession":
    case "UpdateSession":
    case "Clear":
      return state;
  }
};
