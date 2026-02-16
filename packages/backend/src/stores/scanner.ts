import {
  createPrefixedRandomId,
  type Finding,
  type InterruptReason,
  type ScanConfig,
  type ScanRunnable,
} from "engine";
import { create } from "mutative";
import type { CheckExecution, Session } from "shared";

import { SessionsStorage } from "../storage/sessions";
import { type BackendSDK } from "../types";

export class ScannerStore {
  private static instance?: ScannerStore;

  private sessions: Map<string, Session>;
  private runnables: Map<string, ScanRunnable>;
  private sessionsStorage!: SessionsStorage;
  private currentProjectId?: string;
  private saveTimeouts: Map<string, Timeout>;
  private executionTraces: Map<string, string> = new Map();

  private constructor() {
    this.sessions = new Map();
    this.runnables = new Map();
    this.saveTimeouts = new Map();
  }

  static get(): ScannerStore {
    if (!ScannerStore.instance) {
      ScannerStore.instance = new ScannerStore();
    }
    return ScannerStore.instance;
  }

  async initialize(sdk: BackendSDK): Promise<void> {
    this.sessionsStorage = new SessionsStorage(sdk);

    const project = await sdk.projects.getCurrent();
    this.currentProjectId = project?.getId();

    if (this.currentProjectId !== undefined) {
      await this.loadSessions(this.currentProjectId);
    }
  }

  async switchProject(projectId: string | undefined): Promise<void> {
    this.currentProjectId = projectId;
    this.sessions.clear();
    this.runnables.clear();
    this.saveTimeouts.clear();

    if (projectId !== undefined) {
      await this.loadSessions(projectId);
    }
  }

  private async loadSessions(projectId: string): Promise<void> {
    const sessions = await this.sessionsStorage.list(projectId);
    for (const session of sessions) {
      this.sessions.set(session.id, session);
    }
  }

  registerRunnable(id: string, runnable: ScanRunnable) {
    this.runnables.set(id, runnable);
  }

  async cancelRunnable(id: string): Promise<boolean> {
    const runnable = this.runnables.get(id);
    if (!runnable) return false;

    await runnable.cancel("Cancelled");
    return true;
  }

  unregisterRunnable(id: string): boolean {
    return this.runnables.delete(id);
  }

  createSession(
    title: string,
    requestIDs: string[],
    scanConfig: ScanConfig,
  ): Session {
    const id = createPrefixedRandomId("ascan-");
    const session: Session = {
      kind: "Pending",
      id,
      createdAt: Date.now(),
      title,
      requestIDs,
      scanConfig,
    };
    this.sessions.set(id, session);
    this.saveSession(id, session, true);
    return session;
  }

  getSession(id: string): Session | undefined {
    return this.sessions.get(id);
  }

  deleteSession(id: string): boolean {
    const runnable = this.runnables.get(id);
    if (runnable) {
      runnable.cancel("Cancelled");
      this.runnables.delete(id);
    }

    this.executionTraces.delete(id);
    const timeout = this.saveTimeouts.get(id);
    if (timeout !== undefined) {
      clearTimeout(timeout);
      this.saveTimeouts.delete(id);
    }

    if (this.currentProjectId !== undefined) {
      this.sessionsStorage.delete(this.currentProjectId, id);
    }

    return this.sessions.delete(id);
  }

  updateSessionTitle(id: string, title: string): Session | undefined {
    return this.updateSession(id, (draft) => {
      draft.title = title;
    });
  }

  startSession(id: string, checksTotal: number): Session | undefined {
    return this.updateSession(id, (draft) => {
      if (draft.kind !== "Pending") {
        throw new Error(`Cannot start session in state: ${draft.kind}`);
      }

      Object.assign(draft, {
        kind: "Running" as const,
        startedAt: Date.now(),
        progress: {
          checksTotal,
          checksHistory: [],
        },
      });
    });
  }

  addFinding(
    sessionId: string,
    checkId: string,
    targetId: string,
    finding: Finding,
  ): Session | undefined {
    return this.updateSession(sessionId, (draft) => {
      if (draft.kind !== "Running") {
        throw new Error(`Cannot add finding in state: ${draft.kind}`);
      }

      const execution = this.findCheckExecution(
        draft.progress.checksHistory,
        checkId,
        targetId,
      );

      if (execution?.kind === "Running") {
        execution.findings.push(finding);
      }
    });
  }

  addRequestSent(
    sessionId: string,
    checkId: string,
    targetId: string,
    pendingRequestID: string,
  ): Session | undefined {
    return this.updateSession(sessionId, (draft) => {
      if (draft.kind !== "Running") {
        throw new Error(`Cannot add request sent in state: ${draft.kind}`);
      }

      const execution = this.findCheckExecution(
        draft.progress.checksHistory,
        checkId,
        targetId,
      );

      if (execution?.kind === "Running") {
        execution.requestsSent.push({
          status: "pending",
          pendingRequestID,
          sentAt: Date.now(),
        });
      }
    });
  }

  completeRequest(
    sessionId: string,
    pendingRequestID: string,
    requestID: string,
  ): Session | undefined {
    return this.updateSession(sessionId, (draft) => {
      if (draft.kind !== "Running") {
        throw new Error(`Cannot complete request in state: ${draft.kind}`);
      }

      for (const execution of draft.progress.checksHistory) {
        if (execution.kind !== "Running") continue;

        const requestIndex = execution.requestsSent.findIndex(
          (req) => req.pendingRequestID === pendingRequestID,
        );

        if (requestIndex !== -1) {
          const request = execution.requestsSent[requestIndex];
          if (request) {
            execution.requestsSent[requestIndex] = {
              status: "completed",
              pendingRequestID,
              requestID,
              sentAt: request.sentAt,
              completedAt: Date.now(),
            };
          }
          break;
        }
      }
    });
  }

  failRequest(
    sessionId: string,
    pendingRequestID: string,
    error: string,
  ): Session | undefined {
    return this.updateSession(sessionId, (draft) => {
      if (draft.kind !== "Running") {
        throw new Error(`Cannot fail request in state: ${draft.kind}`);
      }

      for (const execution of draft.progress.checksHistory) {
        if (execution.kind !== "Running") continue;

        const requestIndex = execution.requestsSent.findIndex(
          (req) => req.pendingRequestID === pendingRequestID,
        );

        if (requestIndex !== -1) {
          const request = execution.requestsSent[requestIndex];
          if (request) {
            execution.requestsSent[requestIndex] = {
              status: "failed",
              pendingRequestID,
              error,
              sentAt: request.sentAt,
              completedAt: Date.now(),
            };
          }
          break;
        }
      }
    });
  }

  startCheck(
    sessionId: string,
    checkId: string,
    targetId: string,
  ): Session | undefined {
    return this.updateSession(sessionId, (draft) => {
      if (draft.kind !== "Running") {
        throw new Error(`Cannot start check in state: ${draft.kind}`);
      }

      const newExecution: CheckExecution = {
        kind: "Running",
        id: createPrefixedRandomId("check-"),
        checkID: checkId,
        targetRequestID: targetId,
        startedAt: Date.now(),
        requestsSent: [],
        findings: [],
      };

      draft.progress.checksHistory.push(newExecution);
    });
  }

  completeCheck(
    sessionId: string,
    checkId: string,
    targetId: string,
  ): Session | undefined {
    return this.updateSession(sessionId, (draft) => {
      if (draft.kind !== "Running") {
        throw new Error(`Cannot complete check in state: ${draft.kind}`);
      }

      const execution = this.findCheckExecution(
        draft.progress.checksHistory,
        checkId,
        targetId,
      );

      if (execution?.kind === "Running") {
        Object.assign(execution, {
          kind: "Completed" as const,
          completedAt: Date.now(),
        });
      }
    });
  }

  failCheck(
    sessionId: string,
    checkId: string,
    targetId: string,
    error: string,
  ): Session | undefined {
    return this.updateSession(sessionId, (draft) => {
      if (draft.kind !== "Running") {
        throw new Error(`Cannot fail check in state: ${draft.kind}`);
      }

      const execution = this.findCheckExecution(
        draft.progress.checksHistory,
        checkId,
        targetId,
      );

      if (execution?.kind === "Running") {
        Object.assign(execution, {
          kind: "Failed" as const,
          failedAt: Date.now(),
          error,
        });
      }
    });
  }

  finishSession(sessionId: string, trace: string): Session | undefined {
    this.executionTraces.set(sessionId, trace);
    return this.updateSession(sessionId, (draft) => {
      if (draft.kind !== "Running") {
        throw new Error(`Cannot finish session in state: ${draft.kind}`);
      }

      const newSession: Session = {
        ...draft,
        kind: "Done" as const,
        finishedAt: Date.now(),
        hasExecutionTrace: true,
      };

      Object.assign(draft, newSession);
    });
  }

  interruptSession(
    sessionId: string,
    reason: InterruptReason,
    trace: string,
  ): Session | undefined {
    this.executionTraces.set(sessionId, trace);
    return this.updateSession(sessionId, (draft) => {
      if (draft.kind !== "Running") {
        throw new Error(`Cannot interrupt session in state: ${draft.kind}`);
      }

      const newSession: Session = {
        ...draft,
        kind: "Interrupted" as const,
        reason,
        hasExecutionTrace: true,
      };

      Object.assign(draft, newSession);
    });
  }

  errorSession(
    sessionId: string,
    error: string,
    trace: string | undefined,
  ): Session | undefined {
    const hasExecutionTrace = trace !== undefined;
    if (hasExecutionTrace) {
      this.executionTraces.set(sessionId, trace);
    }

    return this.updateSession(sessionId, (draft) => {
      if (
        draft.kind === "Done" ||
        draft.kind === "Error" ||
        draft.kind === "Interrupted"
      ) {
        throw new Error(`Cannot error session in state: ${draft.kind}`);
      }

      const newSession: Session = {
        ...draft,
        kind: "Error" as const,
        error,
        hasExecutionTrace,
      };

      Object.assign(draft, newSession);
    });
  }

  listSessions(): Session[] {
    return Array.from(this.sessions.values());
  }

  private updateSession(
    id: string,
    updater: (draft: Session) => void,
  ): Session | undefined {
    const session = this.sessions.get(id);
    if (!session) return undefined;

    const newSession = create(session, updater);
    this.sessions.set(id, newSession);

    const shouldSaveImmediately =
      newSession.kind === "Done" ||
      newSession.kind === "Error" ||
      newSession.kind === "Interrupted";

    this.saveSession(id, newSession, shouldSaveImmediately);

    return newSession;
  }

  setExecutionTrace(sessionId: string, trace: string): Session | undefined {
    this.executionTraces.set(sessionId, trace);
    return this.updateSession(sessionId, (draft) => {
      if (draft.kind === "Done" || draft.kind === "Interrupted") {
        draft.hasExecutionTrace = true;
      }
    });
  }

  getExecutionTrace(sessionId: string): string | undefined {
    return this.executionTraces.get(sessionId);
  }

  private saveSession(
    id: string,
    session: Session,
    immediate: boolean = false,
  ): void {
    if (this.currentProjectId === undefined) return;

    const isFinishedState =
      session.kind === "Done" ||
      session.kind === "Error" ||
      session.kind === "Interrupted";

    if (!isFinishedState) {
      const existingTimeout = this.saveTimeouts.get(id);
      if (existingTimeout !== undefined) {
        clearTimeout(existingTimeout);
        this.saveTimeouts.delete(id);
      }
      return;
    }

    const existingTimeout = this.saveTimeouts.get(id);
    if (existingTimeout !== undefined) {
      clearTimeout(existingTimeout);
    }

    if (immediate) {
      this.sessionsStorage.save(this.currentProjectId, session);
      this.saveTimeouts.delete(id);
    } else {
      const timeout = setTimeout(() => {
        if (this.currentProjectId !== undefined) {
          this.sessionsStorage.save(this.currentProjectId, session);
        }
        this.saveTimeouts.delete(id);
      }, 2000);
      this.saveTimeouts.set(id, timeout);
    }
  }

  private findCheckExecution(
    checksHistory: CheckExecution[],
    checkId: string,
    targetId: string,
  ): CheckExecution | undefined {
    return checksHistory.find(
      (execution) =>
        execution.checkID === checkId && execution.targetRequestID === targetId,
    );
  }
}
