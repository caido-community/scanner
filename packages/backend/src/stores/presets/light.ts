import type { Preset } from "shared";

import { Checks } from "../../checks";

export const LIGHT_PRESET: Preset = {
  name: "Light",
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
      enabled: true,
    },
    {
      checkID: Checks.ROBOTS_TXT,
      enabled: true,
    },
    {
      checkID: Checks.CORS_MISCONFIG,
      enabled: true,
    },
    {
      checkID: Checks.PHPINFO,
      enabled: false,
    },
    {
      checkID: Checks.GIT_CONFIG,
      enabled: true,
    },
    {
      checkID: Checks.SPRING_ACTUATOR,
      enabled: true,
    },
    {
      checkID: Checks.GRAPHQL_CONTENT_TYPE,
      enabled: false,
    },
    {
      checkID: Checks.BASIC_REFLECTED_XSS,
      enabled: false,
    },
    {
      checkID: Checks.REFLECTED_CSS_INJECTION,
      enabled: false,
    },
    {
      checkID: Checks.MYSQL_ERROR_BASED_SQLI,
      enabled: false,
    },
    {
      checkID: Checks.COMMAND_INJECTION,
      enabled: false,
    },
    {
      checkID: Checks.PATH_TRAVERSAL,
      enabled: false,
    },
    {
      checkID: Checks.SSTI,
      enabled: false,
    },
    {
      checkID: Checks.SUSPECT_TRANSFORM,
      enabled: false,
    },
    {
      checkID: Checks.SECURITY_TXT,
      enabled: false,
    },
    {
      checkID: Checks.DS_STORE_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.SVN_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.NPM_DEBUG_LOG,
      enabled: false,
    },
    {
      checkID: Checks.WEB_CONFIG_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.WORDPRESS_README,
      enabled: false,
    },
    {
      checkID: Checks.HOST_HEADER_INJECTION,
      enabled: false,
    },
    {
      checkID: Checks.TRACE_METHOD_ENABLED,
      enabled: false,
    },
    {
      checkID: Checks.GRAPHQL_INTROSPECTION,
      enabled: false,
    },
    {
      checkID: Checks.XML_INPUT_DETECTION,
      enabled: false,
    },
    {
      checkID: Checks.LARAVEL_DEBUG,
      enabled: false,
    },
    {
      checkID: Checks.SYMFONY_PROFILER,
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
      enabled: false,
    },
    {
      checkID: Checks.JSON_HTML_RESPONSE,
      enabled: true,
    },
    {
      checkID: Checks.OPEN_REDIRECT,
      enabled: false,
    },
    {
      checkID: Checks.REFLECTED_CSS_INJECTION,
      enabled: false,
    },
    {
      checkID: Checks.ANTI_CLICKJACKING,
      enabled: false,
    },
    {
      checkID: Checks.COOKIE_HTTPONLY,
      enabled: false,
    },
    {
      checkID: Checks.COOKIE_SECURE,
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
      checkID: Checks.CREDIT_CARD_DISCLOSURE,
      enabled: false,
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
      enabled: false,
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
      checkID: Checks.AWS_KEY_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.GCP_KEY_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.AZURE_KEY_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.GITHUB_TOKEN_DISCLOSURE,
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
      checkID: Checks.STRIPE_KEY_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.JWT_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.AI_KEY_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.CICD_TOKEN_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.GENERIC_API_KEY,
      enabled: false,
    },
    {
      checkID: Checks.FIREBASE_CONFIG_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.MESSAGING_TOKEN_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.PAYMENT_KEY_DISCLOSURE,
      enabled: false,
    },
    {
      checkID: Checks.SUBDOMAIN_TAKEOVER,
      enabled: false,
    },
    {
      checkID: Checks.DJANGO_DEBUG,
      enabled: false,
    },
  ],
};
