/**
 * Content Security Policy (CSP) parser
 * Parses CSP header values into structured data
 */

export type CSPDirective = {
  name: string;
  values: string[];
};

export type ParsedCSP = {
  directives: CSPDirective[];
  raw: string;
};

export const CSPParser = {
  /**
   * Parse a Content Security Policy header value
   * @param cspHeader - The CSP header value to parse
   * @returns Parsed CSP object with directives and raw value
   */
  parse(cspHeader: string): ParsedCSP {
    if (!cspHeader || cspHeader.trim() === "") {
      return {
        directives: [],
        raw: cspHeader,
      };
    }

    const directives: CSPDirective[] = [];
    const directiveStrings = cspHeader
      .split(";")
      .map((d) => d.trim())
      .filter((d) => d !== "");

    for (const directiveString of directiveStrings) {
      const parts = directiveString.split(/\s+/);
      if (parts.length === 0 || parts[0] === undefined) continue;

      const name = parts[0].trim();
      const values = parts
        .slice(1)
        .map((v) => v.trim())
        .filter((v) => v !== "");

      directives.push({
        name,
        values,
      });
    }

    return {
      directives,
      raw: cspHeader,
    };
  },
};
