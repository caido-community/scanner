import corsMisconfigScan from "./cors-misconfig";
import exposedEnvScan from "./exposed-env";
import gitConfigScan from "./git-config";
import jsonHtmlResponseScan from "./json-html-response";
import openRedirectScan from "./open-redirect";
import phpinfoScan from "./phpinfo";
import { basicReflectedXSSScan } from "./reflected-xss";
import { mysqlErrorBased, mysqlTimeBased } from "./sql-injection";

export type CheckID = (typeof Checks)[keyof typeof Checks];
export const Checks = {
  CORS_MISCONFIG: "cors-misconfig",
  EXPOSED_ENV: "exposed-env",
  GIT_CONFIG: "git-config",
  JSON_HTML_RESPONSE: "json-html-response",
  OPEN_REDIRECT: "open-redirect",
  PHPINFO: "phpinfo",
  BASIC_REFLECTED_XSS: "basic-reflected-xss",
  MYSQL_ERROR_BASED_SQLI: "mysql-error-based-sqli",
  MYSQL_TIME_BASED_SQLI: "mysql-time-based-sqli",
} as const;

export const checks = [
  corsMisconfigScan,
  exposedEnvScan,
  gitConfigScan,
  jsonHtmlResponseScan,
  openRedirectScan,
  phpinfoScan,
  basicReflectedXSSScan,
  mysqlErrorBased,
  mysqlTimeBased,
] as const;
