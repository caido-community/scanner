import { type Session, type SessionProgressPatch } from "shared";
import { reactive } from "vue";

import { type SessionsState } from "@/types/scanner";

type Context = {
  state: SessionsState;
};

type Message =
  | { type: "Start" }
  | { type: "Error"; error: string }
  | { type: "Success"; sessions: Session[] }
  | { type: "AddSession"; session: Session }
  | { type: "UpdateSession"; session: Session }
  | {
      type: "UpdateSessionProgress";
      sessionId: string;
      patch: SessionProgressPatch;
    }
  | { type: "CancelSession"; sessionId: string }
  | { type: "DeleteSession"; sessionId: string }
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

const upsertSession = (
  sessions: Session[],
  nextSession: Session,
): Session[] => {
  const existingIndex = sessions.findIndex(
    (session) => session.id === nextSession.id,
  );

  if (existingIndex === -1) {
    return [...sessions, nextSession];
  }

  return sessions.map((session, index) =>
    index === existingIndex ? nextSession : session,
  );
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
    case "CancelSession":
    case "UpdateSessionProgress":
    case "DeleteSession":
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
    case "CancelSession":
    case "UpdateSessionProgress":
    case "DeleteSession":
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
        sessions: upsertSession(state.sessions, message.session),
      };
    case "UpdateSession":
      return {
        ...state,
        sessions: upsertSession(state.sessions, message.session),
      };
    case "UpdateSessionProgress":
      return {
        ...state,
        sessions: state.sessions.map((session) => {
          if (session.id !== message.sessionId) {
            return session;
          }

          if (
            session.kind !== "Running" &&
            session.kind !== "Done" &&
            session.kind !== "Interrupted"
          ) {
            return session;
          }

          const existingIndex = session.progress.checksHistory.findIndex(
            (execution) => execution.id === message.patch.execution.id,
          );
          const nextChecksHistory =
            existingIndex === -1
              ? [...session.progress.checksHistory, message.patch.execution]
              : session.progress.checksHistory.map((execution, index) =>
                  index === existingIndex ? message.patch.execution : execution,
                );

          return {
            ...session,
            progress: {
              ...session.progress,
              checksHistory: nextChecksHistory,
            },
          };
        }),
      };
    case "DeleteSession":
      return {
        ...state,
        sessions: state.sessions.filter(
          (session) => session.id !== message.sessionId,
        ),
      };
    case "Clear":
      return { type: "Idle" };
    case "Start":
      return { type: "Loading" };
    case "Success":
      return { type: "Success", sessions: message.sessions };
    case "Error":
    case "CancelSession":
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
    case "UpdateSessionProgress":
    case "CancelSession":
    case "DeleteSession":
    case "Clear":
      return { type: "Idle" };
  }
};
