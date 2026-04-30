import type { Severity } from "./severity";

export type Finding = {
  name: string;
  description: string;
  severity: Severity;
  correlation: {
    requestID: string;
    locations: {
      start: number;
      end: number;
      hint?: string;
    }[];
  };
};
