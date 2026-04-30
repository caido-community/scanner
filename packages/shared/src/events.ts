import type { QueueTask } from "./queue";
import type { Session, SessionProgressPatch } from "./session";

export type Events = {
  "session:created": (
    sessionID: string,
    state: Session,
    meta?: { checksTotal?: number },
  ) => void;
  "session:updated": (sessionID: string, state: Session) => void;
  "session:progress": (
    sessionID: string,
    progress: SessionProgressPatch,
  ) => void;
  "passive:queue-updated": (tasks: QueueTask[]) => void;
  "project:changed": (
    projectID: string | undefined,
    phase: "start" | "ready",
  ) => void;
  "config:updated": (projectID: string | undefined) => void;
};
