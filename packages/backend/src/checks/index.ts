import corsMisconfigScan from "./cors-misconfig";
import exposedEnvScan from "./exposed-env";
import gitConfigScan from "./git-config";
import jsonHtmlResponseScan from "./json-html-response";
import openRedirectScan from "./open-redirect";
import pathTraversalScan from "./path-traversal";
import phpinfoScan from "./phpinfo";
import { basicReflectedXSSScan } from "./reflected-xss";
import { mysqlErrorBased } from "./sql-injection";
import sstiScan from "./ssti";

export type CheckID = (typeof Checks)[keyof typeof Checks];
export const Checks = {
  CORS_MISCONFIG: "cors-misconfig",
  EXPOSED_ENV: "exposed-env",
  GIT_CONFIG: "git-config",
  JSON_HTML_RESPONSE: "json-html-response",
  OPEN_REDIRECT: "open-redirect",
  PATH_TRAVERSAL: "path-traversal",
  PHPINFO: "phpinfo",
  BASIC_REFLECTED_XSS: "basic-reflected-xss",
  MYSQL_ERROR_BASED_SQLI: "mysql-error-based-sqli",
  SSTI: "ssti",
  // MYSQL_TIME_BASED_SQLI: "mysql-time-based-sqli" - TODO: fix false positives
} as const;

export const checks = [
  corsMisconfigScan,
  exposedEnvScan,
  gitConfigScan,
  jsonHtmlResponseScan,
  openRedirectScan,
  pathTraversalScan,
  phpinfoScan,
  basicReflectedXSSScan,
  mysqlErrorBased,
  sstiScan,
  // mysqlTimeBased,
] as const;
