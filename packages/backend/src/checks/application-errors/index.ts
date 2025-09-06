import { defineCheck, done, Severity } from "engine";

// Common application error patterns that indicate sensitive information disclosure
const ERROR_PATTERNS = [
  // Database errors
  /mysql_fetch_array\(\)/i,
  /ORA-\d{5}/i, // Oracle errors
  /Microsoft OLE DB Provider for ODBC Drivers/i,
  /\[Microsoft\]\[ODBC SQL Server Driver\]/i,
  /SQLServer JDBC Driver/i,
  /PostgreSQL query failed/i,
  /Warning: mysql_/i,
  /valid MySQL result/i,
  /MySqlClient\./i,

  // Stack traces
  /at \w+\.\w+\(/i,
  /\.java:\d+/i,
  /\.php:\d+/i,
  /\.py:\d+/i,
  /\.rb:\d+/i,
  /Traceback \(most recent call last\)/i,

  // Framework errors
  /Fatal error:/i,
  /Parse error:/i,
  /Warning:/i,
  /Notice:/i,
  /Strict Standards:/i,
  /Deprecated:/i,

  // ASP.NET errors
  /Server Error in '\/' Application/i,
  /System\.Web\.HttpException/i,
  /System\.Data\.SqlClient\.SqlException/i,

  // Java errors
  /java\.lang\./i,
  /Exception in thread/i,
  /Caused by:/i,

  // Generic error indicators
  /error on line \d+/i,
  /syntax error/i,
  /parse error/i,
  /internal server error/i,
  /application error/i,
];

export default defineCheck<{}>(({ step }) => {
  step("checkApplicationErrors", async (state, context) => {
    const { response } = context.target;

    if (!response) {
      return done({ state });
    }

    // Skip successful responses
    if (response.getCode() < 400) {
      return done({ state });
    }

    const body = response.getBody()?.toText();
    if (!body) {
      return done({ state });
    }

    // Check for error patterns
    for (const pattern of ERROR_PATTERNS) {
      if (pattern.test(body)) {
        const finding = {
          name: "Application Error Information Disclosure",
          description: `The application returned an error message that may contain sensitive information. This can help attackers understand the application's internal structure and identify potential vulnerabilities.`,
          severity: Severity.MEDIUM,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        };

        return done({ state, findings: [finding] });
      }
    }

    return done({ state });
  });

  return {
    metadata: {
      id: "application-errors",
      name: "Application Error Information Disclosure",
      description:
        "Detects application error messages that may leak sensitive information about the application's internal structure",
      type: "passive",
      tags: ["information-disclosure", "error-handling"],
      severities: [Severity.MEDIUM],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: (context) =>
      context.request.getHost() +
      context.request.getPort() +
      context.request.getPath(),
    when: (context) =>
      context.response !== undefined && context.response.getCode() >= 400,
  };
});
