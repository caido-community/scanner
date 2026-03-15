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

import {
  createExecutionIndexKey,
  hasSessionProgress,
  recoverSession,
} from "./scanner.utils";

export class ScannerStore {
  private static instance?: ScannerStore;

  private sessions: Map<string, Session>;
  private runnables: Map<string, ScanRunnable>;
  private sessionsStorage!: SessionsStorage;
  private currentProjectId?: string;
  private saveTimeouts: Map<string, Timeout>;
  private executionTraces: Map<string, string> = new Map();
  private executionIndices: Map<string, Map<string, number>>;
  private pendingRequestIndices: Map<
    string,
    { sessionId: string; executionKey: string }
  >;
  private sessionStopWaiters: Map<string, Set<() => void>>;

  private constructor() {
    this.sessions = new Map();
    this.runnables = new Map();
    this.saveTimeouts = new Map();
    this.executionIndices = new Map();
    this.pendingRequestIndices = new Map();
    this.sessionStopWaiters = new Map();
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
    this.clearScheduledSaves();
    this.currentProjectId = projectId;
    this.sessions.clear();
    this.runnables.clear();
    this.executionTraces.clear();
    this.executionIndices.clear();
    this.pendingRequestIndices.clear();
    this.sessionStopWaiters.clear();

    if (projectId !== undefined) {
      await this.loadSessions(projectId);
    }
  }

  private async loadSessions(projectId: string): Promise<void> {
    const sessions = await this.sessionsStorage.list(projectId);
    for (const session of sessions) {
      const recoveredSession = recoverSession(session);
      this.sessions.set(recoveredSession.id, recoveredSession);
      this.reindexSession(recoveredSession);
      if (recoveredSession !== session) {
        await this.sessionsStorage.save(projectId, recoveredSession);
      }
    }
  }

  registerRunnable(id: string, runnable: ScanRunnable) {
    this.runnables.set(id, runnable);
  }

  async cancelRunnable(
    id: string,
    reason: InterruptReason = "Cancelled",
  ): Promise<boolean> {
    const runnable = this.runnables.get(id);
    if (!runnable) return false;

    await runnable.cancel(reason);
    await this.waitForSessionStop(id);
    return true;
  }

  listRunningSessionIds(): string[] {
    return Array.from(this.sessions.values())
      .filter((session) => session.kind === "Running")
      .map((session) => session.id);
  }

  unregisterRunnable(id: string): boolean {
    return this.runnables.delete(id);
  }

  getRunnable(id: string): ScanRunnable | undefined {
    return this.runnables.get(id);
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
    this.executionIndices.delete(id);
    this.sessionStopWaiters.delete(id);
    for (const [
      pendingRequestID,
      index,
    ] of this.pendingRequestIndices.entries()) {
      if (index.sessionId === id) {
        this.pendingRequestIndices.delete(pendingRequestID);
      }
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
    return this.updateSession(
      id,
      (draft) => {
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
      },
      true,
    );
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

      const execution = this.getExecution(draft, sessionId, checkId, targetId);

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

      const execution = this.getExecution(draft, sessionId, checkId, targetId);

      if (execution?.kind === "Running") {
        execution.requestsSent.push({
          status: "pending",
          pendingRequestID,
          sentAt: Date.now(),
        });
        this.pendingRequestIndices.set(pendingRequestID, {
          sessionId,
          executionKey: createExecutionIndexKey({
            sessionId,
            checkId,
            targetId,
          }),
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

      const indexedRequest = this.pendingRequestIndices.get(pendingRequestID);
      if (
        indexedRequest === undefined ||
        indexedRequest.sessionId !== sessionId
      ) {
        return;
      }

      const execution = this.getExecutionByKey(
        draft,
        sessionId,
        indexedRequest.executionKey,
      );
      if (execution?.kind === "Running") {
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
        }
      }

      this.pendingRequestIndices.delete(pendingRequestID);
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

      const indexedRequest = this.pendingRequestIndices.get(pendingRequestID);
      if (
        indexedRequest === undefined ||
        indexedRequest.sessionId !== sessionId
      ) {
        return;
      }

      const execution = this.getExecutionByKey(
        draft,
        sessionId,
        indexedRequest.executionKey,
      );
      if (execution?.kind === "Running") {
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
        }
      }

      this.pendingRequestIndices.delete(pendingRequestID);
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
      const sessionIndices =
        this.executionIndices.get(sessionId) ?? new Map<string, number>();
      sessionIndices.set(
        createExecutionIndexKey({
          sessionId,
          checkId,
          targetId,
        }),
        draft.progress.checksHistory.length - 1,
      );
      this.executionIndices.set(sessionId, sessionIndices);
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

      const execution = this.getExecution(draft, sessionId, checkId, targetId);

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

      const execution = this.getExecution(draft, sessionId, checkId, targetId);

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
    return this.updateSession(
      sessionId,
      (draft) => {
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
      },
      true,
    );
  }

  interruptSession(
    sessionId: string,
    reason: InterruptReason,
    trace: string,
  ): Session | undefined {
    this.executionTraces.set(sessionId, trace);
    return this.updateSession(
      sessionId,
      (draft) => {
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
      },
      true,
    );
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

    return this.updateSession(
      sessionId,
      (draft) => {
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
      },
      true,
    );
  }

  listSessions(): Session[] {
    return Array.from(this.sessions.values());
  }

  private updateSession(
    id: string,
    updater: (draft: Session) => void,
    immediate: boolean = false,
  ): Session | undefined {
    const session = this.sessions.get(id);
    if (!session) return undefined;

    const newSession = create(session, updater);
    this.sessions.set(id, newSession);
    this.reindexSession(newSession);
    this.resolveSessionWaiters(newSession);
    this.saveSession(id, newSession, immediate);

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
    const projectId = this.currentProjectId;
    if (projectId === undefined) return;

    const existingTimeout = this.saveTimeouts.get(id);
    if (existingTimeout !== undefined) {
      clearTimeout(existingTimeout);
    }

    if (immediate) {
      this.sessionsStorage.save(projectId, session);
      this.saveTimeouts.delete(id);
    } else {
      const timeout = setTimeout(() => {
        this.sessionsStorage.save(projectId, session);
        this.saveTimeouts.delete(id);
      }, 1000);
      this.saveTimeouts.set(id, timeout);
    }
  }

  private getExecution(
    session: Extract<Session, { progress: unknown }>,
    sessionId: string,
    checkId: string,
    targetId: string,
  ): CheckExecution | undefined {
    return this.getExecutionByKey(
      session,
      sessionId,
      createExecutionIndexKey({
        sessionId,
        checkId,
        targetId,
      }),
    );
  }

  private getExecutionByKey(
    session: Extract<Session, { progress: unknown }>,
    sessionId: string,
    executionKey: string,
  ): CheckExecution | undefined {
    const sessionIndices = this.executionIndices.get(sessionId);
    const index = sessionIndices?.get(executionKey);
    if (index === undefined) {
      return undefined;
    }

    return session.progress.checksHistory[index];
  }

  getCheckExecution(
    sessionId: string,
    checkId: string,
    targetId: string,
  ): CheckExecution | undefined {
    const session = this.sessions.get(sessionId);
    if (session === undefined || !hasSessionProgress(session)) {
      return undefined;
    }

    return this.getExecution(session, sessionId, checkId, targetId);
  }

  private reindexSession(session: Session): void {
    this.executionIndices.delete(session.id);

    for (const [
      pendingRequestID,
      index,
    ] of this.pendingRequestIndices.entries()) {
      if (index.sessionId === session.id) {
        this.pendingRequestIndices.delete(pendingRequestID);
      }
    }

    if (!hasSessionProgress(session)) {
      return;
    }

    const sessionIndices = new Map<string, number>();
    session.progress.checksHistory.forEach((execution, index) => {
      const key = createExecutionIndexKey({
        sessionId: session.id,
        checkId: execution.checkID,
        targetId: execution.targetRequestID,
      });
      sessionIndices.set(key, index);

      for (const request of execution.requestsSent) {
        if (request.status === "pending") {
          this.pendingRequestIndices.set(request.pendingRequestID, {
            sessionId: session.id,
            executionKey: key,
          });
        }
      }
    });

    this.executionIndices.set(session.id, sessionIndices);
  }

  private resolveSessionWaiters(session: Session): void {
    if (session.kind === "Running") {
      return;
    }

    const waiters = this.sessionStopWaiters.get(session.id);
    if (waiters === undefined) {
      return;
    }

    for (const resolve of waiters) {
      resolve();
    }
    this.sessionStopWaiters.delete(session.id);
  }

  private waitForSessionStop(id: string): Promise<void> {
    const session = this.sessions.get(id);
    if (session === undefined || session.kind !== "Running") {
      return Promise.resolve();
    }

    return new Promise<void>((resolve) => {
      const waiters = this.sessionStopWaiters.get(id) ?? new Set<() => void>();
      waiters.add(resolve);
      this.sessionStopWaiters.set(id, waiters);
    });
  }

  private clearScheduledSaves(): void {
    for (const timeout of this.saveTimeouts.values()) {
      clearTimeout(timeout);
    }
    this.saveTimeouts.clear();
  }
}
