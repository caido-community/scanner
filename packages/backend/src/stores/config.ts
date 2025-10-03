import { ScanAggressivity } from "engine";
import { type UserConfig } from "shared";

import { Checks } from "../checks";

export class ConfigStore {
  private static _store?: ConfigStore;

  private config: UserConfig;

  private constructor() {
    this.config = {
      passive: {
        enabled: true,
        aggressivity: ScanAggressivity.LOW,
        inScopeOnly: true,
        concurrentChecks: 2,
        concurrentRequests: 3,
        overrides: [],
        severities: ["critical", "high", "medium", "low", "info"],
      },
      active: {
        overrides: [],
      },
      presets: [
        {
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
              checkID: Checks.BASIC_REFLECTED_XSS,
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
              checkID: Checks.ANTI_CLICKJACKING,
              enabled: false,
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
              checkID: Checks.HASH_DISCLOSURE,
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
          ],
        },
        {
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
              checkID: Checks.PATH_TRAVERSAL,
              enabled: true,
            },
            {
              checkID: Checks.ANTI_CLICKJACKING,
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
              checkID: Checks.HASH_DISCLOSURE,
              enabled: false,
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
          ],
        },
        {
          name: "Heavy",
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
              checkID: Checks.GIT_CONFIG,
              enabled: true,
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
              checkID: Checks.BASIC_REFLECTED_XSS,
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
              checkID: Checks.ANTI_CLICKJACKING,
              enabled: true,
            },
            {
              checkID: Checks.ROBOTS_TXT,
              enabled: true,
            },
            {
              checkID: Checks.SSTI,
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
              checkID: Checks.ROBOTS_TXT,
              enabled: true,
            },
            {
              checkID: Checks.DIRECTORY_LISTING,
              enabled: true,
            },
            {
              checkID: Checks.COMMAND_INJECTION,
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
              checkID: Checks.GIT_CONFIG,
              enabled: true,
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
              checkID: Checks.BASIC_REFLECTED_XSS,
              enabled: true,
            },
            {
              checkID: Checks.MYSQL_ERROR_BASED_SQLI,
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
              enabled: true,
            },
            {
              checkID: Checks.EMAIL_DISCLOSURE,
              enabled: true,
            },
            {
              checkID: Checks.HASH_DISCLOSURE,
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
          ],
        },
      ],
    };

    // Light preset is selected by default
    const lightPreset = this.config.presets[0];
    if (lightPreset) {
      this.config.active.overrides = lightPreset.active;
      this.config.passive.overrides = lightPreset.passive;
    }
  }

  static get(): ConfigStore {
    if (!ConfigStore._store) {
      ConfigStore._store = new ConfigStore();
    }

    return ConfigStore._store;
  }

  getUserConfig() {
    return { ...this.config };
  }

  updateUserConfig(config: Partial<UserConfig>) {
    Object.assign(this.config, config);
    return this.config;
  }
}
