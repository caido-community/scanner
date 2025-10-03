/**
 * Content Security Policy (CSP) parser
 * Parses CSP header values into structured data using Lezer parser
 */

import { parser } from "./__generated__.js";

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

    const tree = parser.parse(cspHeader);
    const directives: CSPDirective[] = [];

    // Walk the tree to extract directives
    const cursor = tree.cursor();
    do {
      if (cursor.name === "Directive") {
        const directive = this.extractDirective(cursor, cspHeader);
        if (directive) {
          directives.push(directive);
        }
      }
    } while (cursor.next());

    return {
      directives,
      raw: cspHeader,
    };
  },

  /**
   * Extract directive information from a tree cursor
   */
  extractDirective(cursor: any, source: string): CSPDirective | null {
    // Find directive name
    let name = "";
    const values: string[] = [];

    if (cursor.firstChild()) {
      do {
        if (cursor.name === "DirectiveName") {
          name = source.slice(cursor.from, cursor.to);
        } else if (cursor.name === "SourceList") {
          // Extract source values from SourceList
          if (cursor.firstChild()) {
            do {
              if (cursor.name === "SourceValue") {
                const value = source.slice(cursor.from, cursor.to);
                values.push(value);
              }
            } while (cursor.nextSibling());
            cursor.parent();
          }
        }
      } while (cursor.nextSibling());
      cursor.parent();
    }

    if (!name) return null;

    return { name, values };
  },
};
