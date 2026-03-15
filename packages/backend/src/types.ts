import { type DefineEvents, type SDK } from "caido:plugin";
import {
  type QueueTask,
  type Session,
  type SessionProgressPatch,
} from "shared";

import { type API } from ".";

export const Tags = {
  ATTACK_SURFACE: "attack-surface",
  CLICKJACKING: "clickjacking",
  COMMAND_EXECUTION: "command-execution",
  COOKIES: "cookies",
  CORS: "cors",
  CRYPTOGRAPHY: "cryptography",
  CSP: "csp",
  CSRF: "csrf",
  CSS_INJECTION: "css-injection",
  DEBUG: "debug",
  ENFORCEMENT: "enforcement",
  ERROR_HANDLING: "error-handling",
  FORM_ACTION: "form-action",
  FORM_HIJACKING: "form-hijacking",
  FRAME_ANCESTORS: "frame-ancestors",
  GRAPHQL: "graphql",
  HASH: "hash",
  HTTPONLY: "httponly",
  INFORMATION_DISCLOSURE: "information-disclosure",
  INJECTION: "injection",
  INPUT_VALIDATION: "input-validation",
  OPEN_REDIRECT: "open-redirect",
  PASSWORD: "password",
  RCE: "rce",
  REDIRECT: "redirect",
  REPORT_ONLY: "report-only",
  SCRIPT_SRC: "script-src",
  SECURE: "secure",
  SECURITY_HEADERS: "security-headers",
  SENSITIVE_DATA: "sensitive-data",
  SQLI: "sqli",
  SSTI: "ssti",
  STYLE_SRC: "style-src",
  SUPPLY_CHAIN: "supply-chain",
  SYNTAX: "syntax",
  TEMPLATE: "template",
  TLS: "tls",
  UI_REDRESSING: "ui-redressing",
  VALIDATION: "validation",
  XSS: "xss",
  X_FRAME_OPTIONS: "x-frame-options",
} as const;

export type BackendSDK = SDK<API, BackendEvents>;
export type BackendEvents = DefineEvents<{
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
}>;
