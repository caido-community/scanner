import { type CheckContext } from "../types";

export type RedirectionType =
  | "http"
  | "meta-refresh"
  | "meta-location"
  | "refresh-header"
  | "base-tag"
  | "javascript";

export type RedirectionInfo =
  | { hasRedirection: false }
  | { hasRedirection: true; type: RedirectionType; location: string };

/**
 * All browser redirections methods according to:
 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections
 * https://code.google.com/archive/p/html5security/wikis/RedirectionMethods.wiki
 */
export function findRedirection(context: CheckContext): RedirectionInfo {
  if (!context.response) {
    return { hasRedirection: false };
  }

  const response = context.response;

  // HTTP redirects (3xx status codes with Location header)
  const statusCode = response.getCode();
  if (statusCode >= 300 && statusCode < 400) {
    const locations = response.getHeader("Location");
    if (locations && locations.length > 0) {
      return {
        hasRedirection: true,
        type: "http",
        location: locations[0]!,
      };
    }
  }

  // Refresh header (example: "Refresh: 0; url=http://example.com")
  const refreshHeaders = response.getHeader("Refresh");
  if (refreshHeaders && refreshHeaders.length > 0) {
    const refreshContent = refreshHeaders[0];
    if (refreshContent !== undefined && refreshContent !== "") {
      const urlMatch = refreshContent.match(/(?:url\s*=\s*)?(.+)/i);
      if (urlMatch && urlMatch[1] !== undefined && urlMatch[1] !== "") {
        const url = urlMatch[1].replace(/^['"]|['"]$/g, "").trim();

        return {
          hasRedirection: true,
          type: "refresh-header",
          location: url,
        };
      }
    }
  }

  // HTML redirects
  const html = context.runtime.html.get();
  if (html !== undefined) {
    // <meta> refresh redirects
    const metaElements = html.findElements({ tagName: "meta" });

    for (const element of metaElements) {
      const httpEquiv = html.getElementAttribute(element, "http-equiv");

      if (httpEquiv?.toLowerCase() === "refresh") {
        const content = html.getElementAttribute(element, "content");
        if (content !== undefined && content !== "") {
          const urlMatch = content.match(/url\s*=\s*(.+)/i);
          if (urlMatch && urlMatch[1] !== undefined && urlMatch[1] !== "") {
            const url = urlMatch[1].replace(/^['"]|['"]$/g, "").trim();

            return {
              hasRedirection: true,
              type: "meta-refresh",
              location: url,
            };
          }
        }
      } else if (httpEquiv?.toLowerCase() === "location") {
        const content = html.getElementAttribute(element, "content");
        if (content !== undefined && content !== "") {
          return {
            hasRedirection: true,
            type: "meta-location",
            location: content.trim(),
          };
        }
      }
    }

    // <base> tag
    const baseElements = html.findElements({ tagName: "base" });

    for (const element of baseElements) {
      const href = html.getElementAttribute(element, "href");
      if (href !== undefined && href !== "") {
        return {
          hasRedirection: true,
          type: "base-tag",
          location: href.trim(),
        };
      }
    }

    // Redirects inside <script> tag
    const scriptElements = html.findElements({ tagName: "script" });
    for (const element of scriptElements) {
      const content = html.getElementText(element);
      if (content !== undefined && content !== "") {
        const scriptRedirect = detectJavaScriptRedirect(content);
        if (scriptRedirect !== undefined) {
          return {
            hasRedirection: true,
            type: "javascript",
            location: scriptRedirect,
          };
        }
      }
    }
  }

  return { hasRedirection: false };
}

function detectJavaScriptRedirect(scriptContent: string): string | undefined {
  const patterns = [
    // location = 'url' or location.href = 'url'
    /(?:location(?:\.href)?)\s*=\s*['"`]([^'"`]+)['"`]/gi,

    // window.location = 'url' or window.location.href = 'url'
    /window\.location(?:\.href)?\s*=\s*['"`]([^'"`]+)['"`]/gi,

    // document.location = 'url' or document.location.href = 'url'
    /document\.location(?:\.href)?\s*=\s*['"`]([^'"`]+)['"`]/gi,

    // location.replace('url'), location.assign('url'), location.reload('url')
    /location\.(?:replace|assign|reload)\s*\(\s*['"`]([^'"`]+)['"`]/gi,

    // window.open('url'), window.navigate('url')
    /window\.(?:open|navigate)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
  ];

  for (const pattern of patterns) {
    const matches = [...scriptContent.matchAll(pattern)];
    for (const match of matches) {
      if (match[1] !== undefined && match[1] !== "") {
        const url = match[1].trim();
        if (url !== "" && !isCommonNonRedirect(url)) {
          return url;
        }
      }
    }
  }

  return undefined;
}

function isCommonNonRedirect(url: string): boolean {
  const lowerUrl = url.toLowerCase();

  // Skip common non-redirect patterns
  const nonRedirectPatterns = [
    "#",
    "javascript:",
    "mailto:",
    "tel:",
    "sms:",
    "about:blank",
    "data:",
    "blob:",
  ];

  return nonRedirectPatterns.some((pattern) => lowerUrl.startsWith(pattern));
}
