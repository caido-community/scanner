import { defineCheckV2, Result, Severity } from "engine";

import { Tags } from "../../types";
import { containsCanary, generateCanary } from "../../utils/canary";
import { keyStrategy } from "../../utils/key";

export default defineCheckV2({
  id: "trace-method-enabled",
  name: "TRACE Method Enabled",
  description:
    "Detects servers that have the HTTP TRACE method enabled, which echoes back request headers and can facilitate Cross-Site Tracing attacks",
  type: "active",
  tags: [Tags.SECURITY_HEADERS, Tags.INFORMATION_DISCLOSURE],
  severities: [Severity.MEDIUM],
  aggressivity: {
    minRequests: 1,
    maxRequests: 1,
  },
  dedupeKey: keyStrategy().withHost().withPort().build(),

  async execute(ctx) {
    const canary = generateCanary();
    const spec = ctx.target.request.toSpec();
    spec.setMethod("TRACE");
    spec.setQuery("");
    spec.setBody("");
    spec.setHeader("X-Scanner-Trace", canary);

    const result = await ctx.send(spec);
    if (Result.isErr(result)) return;

    const { request, response } = result.value;
    const code = response.getCode();
    const body = response.getBody()?.toText();

    if (code !== 200 || body === undefined) return;

    if (!containsCanary(body, canary)) return;

    ctx.finding({
      name: "TRACE Method Enabled",
      description: `The server has the HTTP TRACE method enabled and echoes back request headers in the response body. The custom header \`X-Scanner-Trace: ${canary}\` was reflected.\n\nThis can be exploited in Cross-Site Tracing (XST) attacks to steal credentials, session tokens, or other sensitive headers.`,
      severity: Severity.MEDIUM,
      request,
      impact:
        "Attackers can use TRACE to read HTTP-only cookies and authorization headers via Cross-Site Tracing, bypassing HttpOnly cookie protections.",
      recommendation:
        "Disable the TRACE method on the web server. In Apache, use `TraceEnable off`. In Nginx, return 405 for TRACE requests.",
    });
  },
});
