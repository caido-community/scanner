import type { Session } from "shared";

export const createExecutionIndexKey = ({
  sessionId,
  checkId,
  targetId,
}: {
  sessionId: string;
  checkId: string;
  targetId: string;
}): string => `${sessionId}:${checkId}:${targetId}`;

export const recoverSession = (session: Session): Session => {
  if (
    session.kind === "Done" ||
    session.kind === "Interrupted" ||
    session.kind === "Error"
  ) {
    return session;
  }

  if (session.kind === "Pending") {
    return {
      id: session.id,
      kind: "Interrupted",
      title: session.title,
      createdAt: session.createdAt,
      startedAt: session.createdAt,
      progress: {
        checksTotal: 0,
        checksHistory: [],
      },
      reason: "RuntimeStopped",
      hasExecutionTrace: false,
      requestIDs: session.requestIDs,
      scanConfig: session.scanConfig,
    };
  }

  return {
    ...session,
    kind: "Interrupted",
    reason: "RuntimeStopped",
    hasExecutionTrace: false,
  };
};

export const hasSessionProgress = (
  session: Session,
): session is Extract<Session, { progress: unknown }> => {
  return (
    session.kind === "Running" ||
    session.kind === "Done" ||
    session.kind === "Interrupted"
  );
};
