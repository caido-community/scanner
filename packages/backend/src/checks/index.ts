import antiClickjackingScan from "./anti-clickjacking";
import applicationErrorsScan from "./application-errors";
import bigRedirectsScan from "./big-redirects";
import commandInjectionScan from "./command-injection";
import corsMisconfigScan from "./cors-misconfig";
import creditCardDisclosureScan from "./credit-card-disclosure";
import cspAllowlistedScriptsScan from "./csp-allowlisted-scripts";
import cspClickjackingScan from "./csp-clickjacking";
import cspFormHijackingScan from "./csp-form-hijacking";
import cspMalformedSyntaxScan from "./csp-malformed-syntax";
import cspNotEnforcedScan from "./csp-not-enforced";
import cspUntrustedScriptScan from "./csp-untrusted-script";
import cspUntrustedStyleScan from "./csp-untrusted-style";
import dbConnectionDisclosureScan from "./db-connection-disclosure";
import debugErrorsScan from "./debug-errors";
import directoryListingScan from "./directory-listing";
import emailDisclosureScan from "./email-disclosure";
import exposedEnvScan from "./exposed-env";
import gitConfigScan from "./git-config";
import { graphqlContentTypeScan, graphqlEndpointScan } from "./graphql";
import hashDisclosureScan from "./hash-disclosure";
import jsonHtmlResponseScan from "./json-html-response";
import linkManipulationScan from "./link-manipulation";
import missingContentTypeScan from "./missing-content-type";
import openRedirectScan from "./open-redirect";
import pathTraversalScan from "./path-traversal";
import phpinfoScan from "./phpinfo";
import privateIpDisclosureScan from "./private-ip-disclosure";
import privateKeyDisclosureScan from "./private-key-disclosure";
import { basicReflectedXSSScan } from "./reflected-xss";
import robotsTxtScan from "./robots-txt";
import springActuatorScan from "./spring-actuator";
import { mysqlErrorBased, mysqlTimeBased } from "./sql-injection";
import sqlStatementInParams from "./sql-statement-in-params";
import ssnDisclosureScan from "./ssn-disclosure";
import sstiScan from "./ssti";
import suspectTransformScan from "./suspect-transform";
import userAgentDependentResponseScan from "./user-agent-dependent-response";

export const Checks = {
  ANTI_CLICKJACKING: "anti-clickjacking",
  APPLICATION_ERRORS: "application-errors",
  BIG_REDIRECTS: "big-redirects",
  COMMAND_INJECTION: "command-injection",
  // COOKIE_HTTPONLY: "cookie-httponly",
  // COOKIE_SECURE: "cookie-secure",
  CORS_MISCONFIG: "cors-misconfig",
  CREDIT_CARD_DISCLOSURE: "credit-card-disclosure",
  CSP_ALLOWLISTED_SCRIPTS: "csp-allowlisted-scripts",
  CSP_CLICKJACKING: "csp-clickjacking",
  CSP_FORM_HIJACKING: "csp-form-hijacking",
  CSP_MALFORMED_SYNTAX: "csp-malformed-syntax",
  CSP_NOT_ENFORCED: "csp-not-enforced",
  CSP_UNTRUSTED_SCRIPT: "csp-untrusted-script",
  CSP_UNTRUSTED_STYLE: "csp-untrusted-style",
  DB_CONNECTION_DISCLOSURE: "db-connection-disclosure",
  DEBUG_ERRORS: "debug-errors",
  DIRECTORY_LISTING: "directory-listing",
  EMAIL_DISCLOSURE: "email-disclosure",
  EXPOSED_ENV: "exposed-env",
  GIT_CONFIG: "git-config",
  GRAPHQL_CONTENT_TYPE: "graphql-content-type",
  GRAPHQL_ENDPOINT: "graphql-endpoint",
  HASH_DISCLOSURE: "hash-disclosure",
  JSON_HTML_RESPONSE: "json-html-response",
  LINK_MANIPULATION: "link-manipulation",
  MISSING_CONTENT_TYPE: "missing-content-type",
  OPEN_REDIRECT: "open-redirect",
  PATH_TRAVERSAL: "path-traversal",
  PHPINFO: "phpinfo",
  PRIVATE_IP_DISCLOSURE: "private-ip-disclosure",
  PRIVATE_KEY_DISCLOSURE: "private-key-disclosure",
  ROBOTS_TXT: "robots-txt",
  BASIC_REFLECTED_XSS: "basic-reflected-xss",
  MYSQL_ERROR_BASED_SQLI: "mysql-error-based-sqli",
  TIME_BASED_SQLI: "time-based-sqli",
  SPRING_ACTUATOR: "spring-actuator",
  SSTI: "ssti",
  SQL_STATEMENT_IN_PARAMS: "sql-statement-in-params",
  SSN_DISCLOSURE: "ssn-disclosure",
  SUSPECT_TRANSFORM: "suspect-transform",
  USER_AGENT_DEPENDENT_RESPONSE: "user-agent-dependent-response",
} as const;

export const checks = [
  antiClickjackingScan,
  applicationErrorsScan,
  bigRedirectsScan,
  commandInjectionScan,
  // cookieHttpOnlyScan,
  // cookieSecureScan,
  corsMisconfigScan,
  creditCardDisclosureScan,
  cspAllowlistedScriptsScan,
  cspClickjackingScan,
  cspFormHijackingScan,
  cspMalformedSyntaxScan,
  cspNotEnforcedScan,
  cspUntrustedScriptScan,
  cspUntrustedStyleScan,
  dbConnectionDisclosureScan,
  debugErrorsScan,
  directoryListingScan,
  emailDisclosureScan,
  exposedEnvScan,
  gitConfigScan,
  graphqlContentTypeScan,
  graphqlEndpointScan,
  hashDisclosureScan,
  jsonHtmlResponseScan,
  linkManipulationScan,
  missingContentTypeScan,
  openRedirectScan,
  pathTraversalScan,
  phpinfoScan,
  privateIpDisclosureScan,
  privateKeyDisclosureScan,
  robotsTxtScan,
  basicReflectedXSSScan,
  mysqlErrorBased,
  mysqlTimeBased,
  springActuatorScan,
  sstiScan,
  sqlStatementInParams,
  ssnDisclosureScan,
  suspectTransformScan,
  userAgentDependentResponseScan,
  // mysqlTimeBased,
] as const;
