import type { Preset } from "shared";

import { Checks } from "../../checks";

export const BALANCED_PRESET: Preset = {
  name: "Balanced",
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
      checkID: Checks.BASIC_REFLECTED_XSS,
      enabled: true,
    },
    {
      checkID: Checks.REFLECTED_CSS_INJECTION,
      enabled: true,
    },
    {
      checkID: Checks.PHPINFO,
      enabled: true,
    },
    {
      checkID: Checks.CORS_MISCONFIG,
      enabled: true,
    },
    {
      checkID: Checks.MYSQL_ERROR_BASED_SQLI,
      enabled: true,
    },
    {
      checkID: Checks.TIME_BASED_SQLI,
      enabled: false,
    },
    {
      checkID: Checks.COMMAND_INJECTION,
      enabled: true,
    },
    {
      checkID: Checks.SSTI,
      enabled: true,
    },
    {
      checkID: Checks.ROBOTS_TXT,
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
      checkID: Checks.PATH_TRAVERSAL,
      enabled: true,
    },
    {
      checkID: Checks.ANTI_CLICKJACKING,
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
    {
      checkID: Checks.USER_AGENT_DEPENDENT_RESPONSE,
      enabled: false,
    },
    {
      checkID: Checks.HOST_HEADER_INJECTION,
      enabled: true,
    },
    {
      checkID: Checks.TRACE_METHOD_ENABLED,
      enabled: true,
    },
    {
      checkID: Checks.GRAPHQL_INTROSPECTION,
      enabled: true,
    },
    {
      checkID: Checks.XML_INPUT_DETECTION,
      enabled: false,
    },
    {
      checkID: Checks.DS_STORE_DISCLOSURE,
      enabled: true,
    },
    {
      checkID: Checks.SVN_DISCLOSURE,
      enabled: true,
    },
    {
      checkID: Checks.NPM_DEBUG_LOG,
      enabled: true,
    },
    {
      checkID: Checks.WEB_CONFIG_DISCLOSURE,
      enabled: true,
    },
    {
      checkID: Checks.WORDPRESS_README,
      enabled: true,
    },
    {
      checkID: Checks.SECURITY_TXT,
      enabled: false,
    },
    {
      checkID: Checks.LARAVEL_DEBUG,
      enabled: true,
    },
    {
      checkID: Checks.SYMFONY_PROFILER,
      enabled: true,
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
      checkID: Checks.OPEN_REDIRECT,
      enabled: true,
    },
    {
      checkID: Checks.MYSQL_ERROR_BASED_SQLI,
      enabled: false,
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
      checkID: Checks.PHPINFO,
      enabled: true,
    },
    {
      checkID: Checks.SSTI,
      enabled: false,
    },
    {
      checkID: Checks.ANTI_CLICKJACKING,
      enabled: true,
    },
    {
      checkID: Checks.COOKIE_HTTPONLY,
      enabled: true,
    },
    {
      checkID: Checks.COOKIE_SECURE,
      enabled: true,
    },
    {
      checkID: Checks.SQL_STATEMENT_IN_PARAMS,
      enabled: true,
    },
    {
      checkID: Checks.APPLICATION_ERRORS,
      enabled: true,
    },
    {
      checkID: Checks.DEBUG_ERRORS,
      enabled: true,
    },
    {
      checkID: Checks.CREDIT_CARD_DISCLOSURE,
      enabled: true,
    },
    {
      checkID: Checks.DB_CONNECTION_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.EMAIL_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.GRAPHQL_ENDPOINT,
      enabled: true,
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
      enabled: true,
    },
    {
      checkID: Checks.PRIVATE_KEY_DISCLOSURE,
      enabled: true,
    },
    {
      checkID: Checks.SSN_DISCLOSURE,
      enabled: true,
    },
    {
      checkID: Checks.CSP_NOT_ENFORCED,
      enabled: true,
    },
    {
      checkID: Checks.CSP_MALFORMED_SYNTAX,
      enabled: true,
    },
    {
      checkID: Checks.CSP_UNTRUSTED_STYLE,
      enabled: true,
    },
    {
      checkID: Checks.CSP_UNTRUSTED_SCRIPT,
      enabled: true,
    },
    {
      checkID: Checks.CSP_FORM_HIJACKING,
      enabled: true,
    },
    {
      checkID: Checks.CSP_CLICKJACKING,
      enabled: true,
    },
    {
      checkID: Checks.CSP_ALLOWLISTED_SCRIPTS,
      enabled: true,
    },
    {
      checkID: Checks.MISSING_CONTENT_TYPE,
      enabled: true,
    },
    {
      checkID: Checks.SOURCEMAP_DISCLOSURE,
      enabled: true,
    },
    {
      checkID: Checks.DJANGO_DEBUG,
      enabled: true,
    },
    {
      checkID: Checks.SUBDOMAIN_TAKEOVER,
      enabled: true,
    },
    {
      checkID: Checks.AWS_KEY_DISCLOSURE,
      enabled: true,
    },
    {
      checkID: Checks.GCP_KEY_DISCLOSURE,
      enabled: true,
    },
    {
      checkID: Checks.AZURE_KEY_DISCLOSURE,
      enabled: true,
    },
    {
      checkID: Checks.GITHUB_TOKEN_DISCLOSURE,
      enabled: true,
    },
    {
      checkID: Checks.STRIPE_KEY_DISCLOSURE,
      enabled: true,
    },
    {
      checkID: Checks.PAYMENT_KEY_DISCLOSURE,
      enabled: true,
    },
    {
      checkID: Checks.JWT_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.AI_KEY_DISCLOSURE,
      enabled: true,
    },
    {
      checkID: Checks.FIREBASE_CONFIG_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.GITLAB_TOKEN_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.SLACK_TOKEN_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.CICD_TOKEN_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.MESSAGING_TOKEN_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.GENERIC_API_KEY,
      enabled: false,
    },
  ],
};
