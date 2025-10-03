/**
 * Content Security Policy (CSP) parser
 * Parses CSP header values into structured data using Lezer parser
 */

import { type TreeCursor } from "@lezer/common";

import { parser } from "./__generated__.js";
import {
  Directive,
  DirectiveName,
  SourceList,
  SourceValue,
} from "./__generated__.terms.js";

export type CSPDirective = {
  name: string;
  values: string[];
};

type ParserResult =
  | {
      kind: "Success";
      directives: CSPDirective[];
      raw: string;
    }
  | {
      kind: "Failed";
    };

const extractDirective = (
  cursor: TreeCursor,
  cspHeader: string,
): CSPDirective | undefined => {
  const node = cursor.node;

  // Get the directive name
  const directiveNameNode = node.getChild(DirectiveName);
  if (!directiveNameNode) return undefined;

  const name = cspHeader.slice(directiveNameNode.from, directiveNameNode.to);
  const values: string[] = [];

  // Look for SourceList in the directive
  const sourceListNode = node.getChild(SourceList);
  if (sourceListNode) {
    // Get all SourceValue nodes by walking through the tree
    const firstChild = sourceListNode.firstChild;
    let child = firstChild;
    while (child) {
      if (child.type && child.type.id === SourceValue) {
        const value = cspHeader.slice(child.from, child.to);
        // Filter out whitespace and empty values
        if (value.trim() !== "") {
          values.push(value);
        }
      }
      child = child.nextSibling;
    }
  }

  return {
    name,
    values,
  };
};

const parse = (cspHeader: string): ParserResult => {
  if (!cspHeader || cspHeader.trim() === "") {
    return {
      kind: "Success",
      directives: [],
      raw: cspHeader,
    };
  }

  const tree = parser.parse(cspHeader);
  const directives: CSPDirective[] = [];

  // Walk the tree to extract directives
  const cursor = tree.cursor();
  do {
    if (cursor.type.id === Directive) {
      const directive = extractDirective(cursor, cspHeader);
      if (directive) {
        directives.push(directive);
      }
    }
  } while (cursor.next());

  return {
    kind: "Success",
    directives,
    raw: cspHeader,
  };
};

export const CSPParser = {
  parse,
};
