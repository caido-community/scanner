import { type CheckTarget } from "../../../types";
import { parseHtml } from "../../../utils/html";
import { type ParsedHtml } from "../../../utils/html/types";

export class HtmlCache {
  private cache = new Map<string, ParsedHtml>();

  get(target: CheckTarget): ParsedHtml | undefined {
    const response = target.response;
    if (response) {
      const responseId = response.getId();
      if (!this.cache.has(responseId)) {
        const html = parseHtml(response);
        if (html) {
          this.cache.set(responseId, html);
        }
      }
      return this.cache.get(responseId);
    }
    return undefined;
  }
}
