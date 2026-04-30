import { defineCheck, done, type Finding, Severity } from "engine";

import { extractParameters } from "../../utils";
import { keyStrategy } from "../../utils/key";
import { Tags } from "../tags";

const hasTokenPair = (
  value: string,
  a: RegExp,
  b: RegExp,
  maxGap: number,
): boolean => {
  const lower = value.toLowerCase();
  const matchA = a.exec(lower);
  if (matchA === null) return false;

  const startAfterA = matchA.index + matchA[0].length;
  const slice = lower.slice(startAfterA, startAfterA + maxGap);
  return b.test(slice);
};

const containsAny = (value: string, patterns: RegExp[]): boolean => {
  for (const p of patterns) {
    if (p.test(value)) return true;
  }
  return false;
};

const hasMultipleSqlKeywords = (value: string): boolean => {
  const keywords = [
    /\bselect\b/i,
    /\bfrom\b/i,
    /\bwhere\b/i,
    /\border\s+by\b/i,
    /\bgroup\s+by\b/i,
    /\blimit\b/i,
    /\binsert\b/i,
    /\bupdate\b/i,
    /\bdelete\b/i,
    /\bunion\b/i,
    /\bjoin\b/i,
    /\binto\b/i,
    /\bvalues\b/i,
    /\bset\b/i,
    /\bdrop\b/i,
    /\bcreate\b/i,
    /\btable\b/i,
    /\bdatabase\b/i,
    /\bindex\b/i,
    /\balter\b/i,
  ];

  let matchCount = 0;
  for (const keyword of keywords) {
    if (keyword.test(value)) {
      matchCount++;
      if (matchCount >= 2) return true;
    }
  }
  return false;
};

const hasSqlInjectionPatterns = (value: string): boolean => {
  const injectionPatterns = [
    /'\s*or\s*'1'\s*=\s*'1/i,
    /'\s*or\s*1\s*=\s*1/i,
    /'\s*and\s*'1'\s*=\s*'1/i,
    /'\s*and\s*1\s*=\s*1/i,
    /--/,
    /\/\*.*?\*\//,
    /;\s*drop/i,
    /;\s*delete/i,
    /;\s*update/i,
    /;\s*insert/i,
    /;\s*create/i,
    /;\s*alter/i,
    /union\s+all\s+select/i,
    /union\s+select/i,
    /'\s*waitfor\s+delay/i,
    /'\s*benchmark\s*\(/i,
    /'\s*sleep\s*\(/i,
    /'\s*pg_sleep\s*\(/i,
    /information_schema/i,
    /sysobjects/i,
    /syscolumns/i,
    /mysql\.user/i,
    /pg_tables/i,
  ];

  return containsAny(value, injectionPatterns);
};

const isLikelySqlStatement = (raw: string) => {
  const value = raw.trim();
  if (value.length < 10) return { matched: false };

  const sqlDelims = [/['"`]/, /--/, /\/\*/, /\)/, /\(/, /=/, /\*/, /;/, /,/];

  if (hasTokenPair(value, /\bunion\s+all\s+select\b/i, /\bfrom\b/i, 100)) {
    return { matched: true, pattern: "union-all-select" };
  }
  if (hasTokenPair(value, /\bunion\s+select\b/i, /\bfrom\b/i, 100)) {
    return { matched: true, pattern: "union-select" };
  }
  if (hasTokenPair(value, /\binsert\s+into\b/i, /\bvalues\s*\(/i, 200)) {
    return { matched: true, pattern: "insert-into-values" };
  }
  if (
    hasTokenPair(value, /\bupdate\b/i, /\bset\b/i, 200) &&
    /\bwhere\b/i.test(value)
  ) {
    return { matched: true, pattern: "update-set-where" };
  }
  if (hasTokenPair(value, /\bdelete\s+from\b/i, /\bwhere\b/i, 200)) {
    return { matched: true, pattern: "delete-from-where" };
  }
  if (
    hasTokenPair(
      value,
      /\bdrop\s+(table|database|index)\b/i,
      /\b[a-z_][a-z0-9_]*\b/i,
      100,
    )
  ) {
    return { matched: true, pattern: "drop-statement" };
  }
  if (
    hasTokenPair(
      value,
      /\bcreate\s+(table|database|index)\b/i,
      /\b[a-z_][a-z0-9_]*\b/i,
      120,
    )
  ) {
    return { matched: true, pattern: "create-statement" };
  }
  if (
    hasTokenPair(value, /\balter\s+table\b/i, /\b(add|drop|modify)\b/i, 120)
  ) {
    return { matched: true, pattern: "alter-table" };
  }
  if (hasTokenPair(value, /\bwith\b/i, /\bas\s*\(/i, 60)) {
    return { matched: true, pattern: "with-cte" };
  }
  if (/\bexec(ute)?\s+/i.test(value) && /\(.*\)/i.test(value)) {
    return { matched: true, pattern: "exec-procedure" };
  }

  if (hasSqlInjectionPatterns(value)) {
    return { matched: true, pattern: "sql-injection" };
  }

  const selectFrom = hasTokenPair(value, /\bselect\b/i, /\bfrom\b/i, 200);
  if (selectFrom) {
    const hasStrongIndicators =
      containsAny(value, sqlDelims) ||
      /\bjoin\b/i.test(value) ||
      /\bwhere\b/i.test(value) ||
      hasMultipleSqlKeywords(value);

    const hasWeakIndicators = /\b(id|name|user|admin|password|email)\b/i.test(
      value,
    );

    if (hasStrongIndicators && !hasWeakIndicators) {
      return { matched: true, pattern: "select-from" };
    }

    if (
      hasStrongIndicators &&
      hasWeakIndicators &&
      containsAny(value, [/['"`]/])
    ) {
      return { matched: true, pattern: "select-from-suspicious" };
    }
  }

  if (hasMultipleSqlKeywords(value) && containsAny(value, sqlDelims)) {
    const suspiciousPatterns = [
      /\b(users?|admin|accounts?|credentials?|passwords?)\b/i,
      /information_schema/i,
      /\bschema\b/i,
      /\btables?\b/i,
      /\bcolumns?\b/i,
    ];

    if (containsAny(value, suspiciousPatterns)) {
      return { matched: true, pattern: "multi-keyword-suspicious" };
    }
  }

  return { matched: false };
};

export default defineCheck<Record<never, never>>(({ step }) => {
  step("scanParameters", (state, context) => {
    const params = extractParameters(context);
    if (params.length === 0) {
      return done({ state });
    }

    const findings: Finding[] = [];

    for (const param of params) {
      const detection = isLikelySqlStatement(param.value);
      if (detection.matched) {
        findings.push({
          name: "SQL Statement Detected in Parameter '" + param.name + "'",
          description:
            "Parameter `" +
            param.name +
            "` in " +
            param.source +
            " appears to contain an SQL statement (" +
            (detection.pattern ?? "sql") +
            "). Supplying raw SQL via parameters can lead to severe injection and logic abuse.",
          severity: Severity.INFO,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        });
      }
    }

    return done({ state, findings });
  });

  return {
    metadata: {
      id: "sql-statement-in-params",
      name: "SQL Statement in Parameters",
      description:
        "Detects parameters that appear to contain full SQL statements such as UNION SELECT, INSERT, UPDATE, DELETE, DROP, CREATE.",
      type: "passive",
      tags: [Tags.SQLI, Tags.INPUT_VALIDATION],
      severities: [Severity.INFO],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy()
      .withMethod()
      .withHost()
      .withPort()
      .withPath()
      .withQueryKeys()
      .build(),
    when: (target) => {
      const query = target.request.getQuery();
      const hasQuery = query !== undefined && query.length > 0;
      const hasBody = target.request.getBody() !== undefined;
      return hasQuery || hasBody;
    },
  };
});
