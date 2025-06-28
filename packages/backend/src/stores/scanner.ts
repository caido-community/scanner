import { type Finding, type InterruptReason } from "engine";
import { type SessionState } from "shared";

export type ScanMessage =
  | { type: "Start" }
  | { type: "AddFinding"; finding: Finding }
  | { type: "AddRequestSent" }
  | { type: "AddCheckCompleted" }
  | { type: "Finish"; findings: Finding[] }
  | { type: "Interrupted"; reason: InterruptReason }
  | { type: "Error"; error: string };

export class ScannerStore {
  private static _store?: ScannerStore;
  private sessions: SessionState[] = [];

  private constructor() {
    this.sessions = [];
  }

  static get(): ScannerStore {
    if (!ScannerStore._store) {
      ScannerStore._store = new ScannerStore();
    }

    return ScannerStore._store;
  }

  createSession(): SessionState {
    const id = crypto.randomUUID();
    const session: SessionState = {
      kind: "Pending",
      id,
      createdAt: Date.now(),
    };
    this.sessions.push(session);
    return session;
  }

  getSession(id: string): SessionState | undefined {
    return this.sessions.find((session) => session.id === id);
  }

  send(id: string, message: ScanMessage): SessionState {
    const session = this.sessions.find((session) => session.id === id);
    if (!session) throw new Error(`Session ${id} not found`);

    let newState: SessionState;
    switch (session.kind) {
      case "Pending":
        newState = processPending(session, message);
        break;
      case "Running":
        newState = processRunning(session, message);
        break;
      case "Done":
        newState = processDone(session, message);
        break;
      case "Error":
        newState = processError(session, message);
        break;
      case "Interrupted":
        newState = processInterrupted(session, message);
        break;
    }

    this.sessions = this.sessions.map((s) => (s.id === id ? newState : s));

    return newState;
  }

  listSessions(): SessionState[] {
    return [...this.sessions];
  }
}

const processPending = (
  state: SessionState & { kind: "Pending" },
  message: ScanMessage,
): SessionState => {
  if (message.type === "Start") {
    return {
      kind: "Running",
      id: state.id,
      createdAt: state.createdAt,
      startedAt: Date.now(),
      findings: [],
      progress: {
        checksCompleted: 0,
        requestsSent: 0,
      },
    };
  }
  throw new Error(`Invalid message '${message.type}' in state '${state.kind}'`);
};

const processRunning = (
  state: SessionState & { kind: "Running" },
  message: ScanMessage,
): SessionState => {
  if (message.type === "Finish") {
    return {
      kind: "Done",
      id: state.id,
      createdAt: state.createdAt,
      startedAt: state.startedAt,
      finishedAt: Date.now(),
      findings: message.findings,
      progress: {
        checksCompleted: state.progress.checksCompleted,
        requestsSent: state.progress.requestsSent,
      },
    };
  }
  if (message.type === "AddFinding") {
    return {
      ...state,
      findings: [...state.findings, message.finding],
    };
  }
  if (message.type === "AddRequestSent") {
    return {
      ...state,
      progress: {
        ...state.progress,
        requestsSent: state.progress.requestsSent + 1,
      },
    };
  }
  if (message.type === "AddCheckCompleted") {
    return {
      ...state,
      progress: {
        ...state.progress,
        checksCompleted: state.progress.checksCompleted + 1,
      },
    };
  }
  if (message.type === "Error") {
    return {
      kind: "Error",
      id: state.id,
      createdAt: state.createdAt,
      error: message.error,
    };
  }
  if (message.type === "Interrupted") {
    return {
      kind: "Interrupted",
      id: state.id,
      createdAt: state.createdAt,
      startedAt: state.startedAt,
      findings: state.findings,
      reason: message.reason,
    };
  }
  throw new Error(`Invalid message '${message.type}' in state '${state.kind}'`);
};

const processDone = (
  state: SessionState & { kind: "Done" },
  message: ScanMessage,
): SessionState => {
  throw new Error(`Invalid message '${message.type}' in state '${state.kind}'`);
};

const processError = (
  state: SessionState & { kind: "Error" },
  message: ScanMessage,
): SessionState => {
  throw new Error(`Invalid message '${message.type}' in state '${state.kind}'`);
};

const processInterrupted = (
  state: SessionState & { kind: "Interrupted" },
  message: ScanMessage,
): SessionState => {
  throw new Error(`Invalid message '${message.type}' in state '${state.kind}'`);
};
