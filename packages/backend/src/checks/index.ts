import aiKeyDisclosureScan from "./ai-key-disclosure";
import antiClickjackingScan from "./anti-clickjacking";
import applicationErrorsScan from "./application-errors";
import awsKeyDisclosureScan from "./aws-key-disclosure";
import azureKeyDisclosureScan from "./azure-key-disclosure";
import bigRedirectsScan from "./big-redirects";
import cicdTokenDisclosureScan from "./cicd-token-disclosure";
import commandInjectionScan from "./command-injection";
import cookieHttpOnlyScan from "./cookie-httponly";
import cookieSecureScan from "./cookie-secure";
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
import djangoDebugScan from "./django-debug";
import dsStoreDisclosureScan from "./ds-store-disclosure";
import emailDisclosureScan from "./email-disclosure";
import exposedEnvScan from "./exposed-env";
import firebaseConfigDisclosureScan from "./firebase-config-disclosure";
import gcpKeyDisclosureScan from "./gcp-key-disclosure";
import genericApiKeyScan from "./generic-api-key";
import gitConfigScan from "./git-config";
import githubTokenDisclosureScan from "./github-token-disclosure";
import gitlabTokenDisclosureScan from "./gitlab-token-disclosure";
import {
  graphqlContentTypeScan,
  graphqlEndpointScan,
  graphqlIntrospectionScan,
} from "./graphql";
import hashDisclosureScan from "./hash-disclosure";
import hostHeaderInjectionScan from "./host-header-injection";
import jsonHtmlResponseScan from "./json-html-response";
import jwtDisclosureScan from "./jwt-disclosure";
import laravelDebugScan from "./laravel-debug";
import linkManipulationScan from "./link-manipulation";
import messagingTokenDisclosureScan from "./messaging-token-disclosure";
import missingContentTypeScan from "./missing-content-type";
import npmDebugLogScan from "./npm-debug-log";
import openRedirectScan from "./open-redirect";
import pathTraversalScan from "./path-traversal";
import paymentKeyDisclosureScan from "./payment-key-disclosure";
import phpinfoScan from "./phpinfo";
import privateIpDisclosureScan from "./private-ip-disclosure";
import privateKeyDisclosureScan from "./private-key-disclosure";
import reflectedCssInjectionScan from "./reflected-css-injection";
import { basicReflectedXSSScan } from "./reflected-xss";
import robotsTxtScan from "./robots-txt";
import securityTxtScan from "./security-txt";
import slackTokenDisclosureScan from "./slack-token-disclosure";
import sourcemapDisclosureScan from "./sourcemap-disclosure";
import springActuatorScan from "./spring-actuator";
import { mysqlErrorBased, mysqlTimeBased } from "./sql-injection";
import sqlStatementInParams from "./sql-statement-in-params";
import ssnDisclosureScan from "./ssn-disclosure";
import sstiScan from "./ssti";
import stripeKeyDisclosureScan from "./stripe-key-disclosure";
import subdomainTakeoverScan from "./subdomain-takeover";
import suspectTransformScan from "./suspect-transform";
import svnDisclosureScan from "./svn-disclosure";
import symfonyProfilerScan from "./symfony-profiler";
import traceMethodEnabledScan from "./trace-method-enabled";
import userAgentDependentResponseScan from "./user-agent-dependent-response";
import webConfigDisclosureScan from "./web-config-disclosure";
import wordpressReadmeScan from "./wordpress-readme";
import xmlInputDetectionScan from "./xml-input-detection";

export const Checks = {
  AI_KEY_DISCLOSURE: "ai-key-disclosure",
  ANTI_CLICKJACKING: "anti-clickjacking",
  APPLICATION_ERRORS: "application-errors",
  AWS_KEY_DISCLOSURE: "aws-key-disclosure",
  AZURE_KEY_DISCLOSURE: "azure-key-disclosure",
  BIG_REDIRECTS: "big-redirects",
  CICD_TOKEN_DISCLOSURE: "cicd-token-disclosure",
  COMMAND_INJECTION: "command-injection",
  COOKIE_HTTPONLY: "cookie-httponly",
  COOKIE_SECURE: "cookie-secure",
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
  DJANGO_DEBUG: "django-debug",
  DS_STORE_DISCLOSURE: "ds-store-disclosure",
  EMAIL_DISCLOSURE: "email-disclosure",
  EXPOSED_ENV: "exposed-env",
  FIREBASE_CONFIG_DISCLOSURE: "firebase-config-disclosure",
  GCP_KEY_DISCLOSURE: "gcp-key-disclosure",
  GENERIC_API_KEY: "generic-api-key",
  GIT_CONFIG: "git-config",
  GITHUB_TOKEN_DISCLOSURE: "github-token-disclosure",
  GITLAB_TOKEN_DISCLOSURE: "gitlab-token-disclosure",
  GRAPHQL_CONTENT_TYPE: "graphql-content-type",
  GRAPHQL_ENDPOINT: "graphql-endpoint",
  GRAPHQL_INTROSPECTION: "graphql-introspection",
  HASH_DISCLOSURE: "hash-disclosure",
  HOST_HEADER_INJECTION: "host-header-injection",
  JSON_HTML_RESPONSE: "json-html-response",
  JWT_DISCLOSURE: "jwt-disclosure",
  LARAVEL_DEBUG: "laravel-debug",
  LINK_MANIPULATION: "link-manipulation",
  MESSAGING_TOKEN_DISCLOSURE: "messaging-token-disclosure",
  MISSING_CONTENT_TYPE: "missing-content-type",
  NPM_DEBUG_LOG: "npm-debug-log",
  OPEN_REDIRECT: "open-redirect",
  PATH_TRAVERSAL: "path-traversal",
  PAYMENT_KEY_DISCLOSURE: "payment-key-disclosure",
  PHPINFO: "phpinfo",
  PRIVATE_IP_DISCLOSURE: "private-ip-disclosure",
  PRIVATE_KEY_DISCLOSURE: "private-key-disclosure",
  REFLECTED_CSS_INJECTION: "reflected-css-injection",
  ROBOTS_TXT: "robots-txt",
  BASIC_REFLECTED_XSS: "basic-reflected-xss",
  MYSQL_ERROR_BASED_SQLI: "mysql-error-based-sqli",
  TIME_BASED_SQLI: "time-based-sqli",
  SECURITY_TXT: "security-txt",
  SLACK_TOKEN_DISCLOSURE: "slack-token-disclosure",
  SOURCEMAP_DISCLOSURE: "sourcemap-disclosure",
  SPRING_ACTUATOR: "spring-actuator",
  SSTI: "ssti",
  SQL_STATEMENT_IN_PARAMS: "sql-statement-in-params",
  SSN_DISCLOSURE: "ssn-disclosure",
  STRIPE_KEY_DISCLOSURE: "stripe-key-disclosure",
  SUBDOMAIN_TAKEOVER: "subdomain-takeover",
  SUSPECT_TRANSFORM: "suspect-transform",
  SVN_DISCLOSURE: "svn-disclosure",
  SYMFONY_PROFILER: "symfony-profiler",
  TRACE_METHOD_ENABLED: "trace-method-enabled",
  USER_AGENT_DEPENDENT_RESPONSE: "user-agent-dependent-response",
  WEB_CONFIG_DISCLOSURE: "web-config-disclosure",
  WORDPRESS_README: "wordpress-readme",
  XML_INPUT_DETECTION: "xml-input-detection",
} as const;

export const checks = [
  aiKeyDisclosureScan,
  antiClickjackingScan,
  applicationErrorsScan,
  awsKeyDisclosureScan,
  azureKeyDisclosureScan,
  bigRedirectsScan,
  cicdTokenDisclosureScan,
  commandInjectionScan,
  cookieHttpOnlyScan,
  cookieSecureScan,
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
  djangoDebugScan,
  dsStoreDisclosureScan,
  emailDisclosureScan,
  exposedEnvScan,
  firebaseConfigDisclosureScan,
  gcpKeyDisclosureScan,
  genericApiKeyScan,
  gitConfigScan,
  githubTokenDisclosureScan,
  gitlabTokenDisclosureScan,
  graphqlContentTypeScan,
  graphqlEndpointScan,
  graphqlIntrospectionScan,
  hashDisclosureScan,
  hostHeaderInjectionScan,
  jsonHtmlResponseScan,
  jwtDisclosureScan,
  laravelDebugScan,
  linkManipulationScan,
  messagingTokenDisclosureScan,
  missingContentTypeScan,
  npmDebugLogScan,
  openRedirectScan,
  pathTraversalScan,
  paymentKeyDisclosureScan,
  phpinfoScan,
  privateIpDisclosureScan,
  privateKeyDisclosureScan,
  reflectedCssInjectionScan,
  robotsTxtScan,
  basicReflectedXSSScan,
  mysqlErrorBased,
  mysqlTimeBased,
  securityTxtScan,
  slackTokenDisclosureScan,
  sourcemapDisclosureScan,
  springActuatorScan,
  sstiScan,
  sqlStatementInParams,
  ssnDisclosureScan,
  stripeKeyDisclosureScan,
  subdomainTakeoverScan,
  suspectTransformScan,
  svnDisclosureScan,
  symfonyProfilerScan,
  traceMethodEnabledScan,
  userAgentDependentResponseScan,
  webConfigDisclosureScan,
  wordpressReadmeScan,
  xmlInputDetectionScan,
] as const;
