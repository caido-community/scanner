import { type Severity } from "engine";
import { type BasicRequest, type Session } from "shared";

export type SessionFinding = {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  checkID: string;
  checkStatus: string;
  targetRequestID: string;
  findingRequestID: string;
};

export type RequestPreviewState =
  | { type: "Idle" }
  | { type: "Loading" }
  | { type: "Error"; error: string }
  | {
      type: "Success";
      request: BasicRequest & { raw: string };
      response: { id: string; raw: string };
    };

export const createSessionFindings = (session: Session): SessionFinding[] => {
  if (
    session.kind !== "Running" &&
    session.kind !== "Done" &&
    session.kind !== "Interrupted"
  ) {
    return [];
  }

  return session.progress.checksHistory.flatMap((check) => {
    return check.findings.map((finding, index) => {
      return {
        id: `${check.id}:${index}:${finding.correlation.requestID}`,
        name: finding.name,
        description: finding.description,
        severity: finding.severity,
        checkID: check.checkID,
        checkStatus: check.kind,
        targetRequestID: check.targetRequestID,
        findingRequestID: finding.correlation.requestID,
      };
    });
  });
};
