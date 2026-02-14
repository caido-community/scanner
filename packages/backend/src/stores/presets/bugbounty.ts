import type { Preset } from "shared";

import { Checks } from "../../checks";

export const BUGBOUNTY_PRESET: Preset = {
  name: "Bug Bounty",
  active: [
    {
      checkID: Checks.EXPOSED_ENV,
      enabled: true,
    },
    {
      checkID: Checks.DIRECTORY_LISTING,
      enabled: true,
    },
    {
      checkID: Checks.JSON_HTML_RESPONSE,
      enabled: true,
    },
    {
      checkID: Checks.OPEN_REDIRECT,
      enabled: true,
    },
    {
      checkID: Checks.ANTI_CLICKJACKING,
      enabled: false,
    },
    {
      checkID: Checks.ROBOTS_TXT,
      enabled: false,
    },
    {
      checkID: Checks.CORS_MISCONFIG,
      enabled: true,
    },
    {
      checkID: Checks.PHPINFO,
      enabled: true,
    },
    {
      checkID: Checks.GIT_CONFIG,
      enabled: true,
    },
    {
      checkID: Checks.GRAPHQL_CONTENT_TYPE,
      enabled: true,
    },
    {
      checkID: Checks.BASIC_REFLECTED_XSS,
      enabled: true,
    },
    {
      checkID: Checks.REFLECTED_CSS_INJECTION,
      enabled: true,
    },
    {
      checkID: Checks.MYSQL_ERROR_BASED_SQLI,
      enabled: true,
    },
    {
      checkID: Checks.TIME_BASED_SQLI,
      enabled: true,
    },
    {
      checkID: Checks.COMMAND_INJECTION,
      enabled: true,
    },
    {
      checkID: Checks.PATH_TRAVERSAL,
      enabled: true,
    },
    {
      checkID: Checks.SSTI,
      enabled: true,
    },
    {
      checkID: Checks.SUSPECT_TRANSFORM,
      enabled: true,
    },
    {
      checkID: Checks.SPRING_ACTUATOR,
      enabled: false,
    },
  ],
  passive: [
    {
      checkID: Checks.BIG_REDIRECTS,
      enabled: true,
    },
    {
      checkID: Checks.EXPOSED_ENV,
      enabled: true,
    },
    {
      checkID: Checks.JSON_HTML_RESPONSE,
      enabled: true,
    },
    {
      checkID: Checks.DIRECTORY_LISTING,
      enabled: true,
    },
    {
      checkID: Checks.OPEN_REDIRECT,
      enabled: true,
    },
    {
      checkID: Checks.ANTI_CLICKJACKING,
      enabled: false,
    },
    {
      checkID: Checks.SQL_STATEMENT_IN_PARAMS,
      enabled: false,
    },
    {
      checkID: Checks.APPLICATION_ERRORS,
      enabled: false,
    },
    {
      checkID: Checks.DEBUG_ERRORS,
      enabled: false,
    },
    {
      checkID: Checks.GIT_CONFIG,
      enabled: true,
    },
    {
      checkID: Checks.GRAPHQL_CONTENT_TYPE,
      enabled: true,
    },
    {
      checkID: Checks.GRAPHQL_ENDPOINT,
      enabled: true,
    },
    {
      checkID: Checks.CREDIT_CARD_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.DB_CONNECTION_DISCLOSURE,
      enabled: true,
    },
    {
      checkID: Checks.EMAIL_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.HASH_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.LINK_MANIPULATION,
      enabled: true,
    },
    {
      checkID: Checks.PRIVATE_IP_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.PRIVATE_KEY_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.SSN_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.CSP_NOT_ENFORCED,
      enabled: false,
    },
    {
      checkID: Checks.CSP_MALFORMED_SYNTAX,
      enabled: false,
    },
    {
      checkID: Checks.CSP_UNTRUSTED_STYLE,
      enabled: false,
    },
    {
      checkID: Checks.CSP_UNTRUSTED_SCRIPT,
      enabled: false,
    },
    {
      checkID: Checks.CSP_FORM_HIJACKING,
      enabled: false,
    },
    {
      checkID: Checks.CSP_CLICKJACKING,
      enabled: false,
    },
    {
      checkID: Checks.CSP_ALLOWLISTED_SCRIPTS,
      enabled: false,
    },
    {
      checkID: Checks.MISSING_CONTENT_TYPE,
      enabled: true,
    },
    {
      checkID: Checks.PHPINFO,
      enabled: true,
    },
    {
      checkID: Checks.BASIC_REFLECTED_XSS,
      enabled: true,
    },
    {
      checkID: Checks.REFLECTED_CSS_INJECTION,
      enabled: true,
    },
    {
      checkID: Checks.MYSQL_ERROR_BASED_SQLI,
      enabled: true,
    },
    {
      checkID: Checks.COMMAND_INJECTION,
      enabled: true,
    },
    {
      checkID: Checks.PATH_TRAVERSAL,
      enabled: true,
    },
    {
      checkID: Checks.SSTI,
      enabled: true,
    },
    {
      checkID: Checks.SUSPECT_TRANSFORM,
      enabled: true,
    },
    {
      checkID: Checks.SPRING_ACTUATOR,
      enabled: true,
    },
  ],
};
