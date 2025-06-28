import type { SessionState } from "shared";

export type SessionsState =
  | { type: "Idle" }
  | { type: "Loading" }
  | { type: "Error"; error: string }
  | { type: "Success"; sessions: SessionState[] };

export type SessionsSelectionState =
  | { type: "None" }
  | { type: "Loading"; sessionId: string }
  | { type: "Error"; sessionId: string; error: string }
  | {
      type: "Success";
      session: SessionState;
    };
