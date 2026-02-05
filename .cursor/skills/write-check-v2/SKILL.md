---
name: write-check-v2
description: Write security checks using the CheckDefinitionV2 system. Use when creating new checks, converting V1 checks to V2, or when the user asks to implement a vulnerability scanner check. Covers defineCheckV2, defineRegexCheck, CheckContext API, parameter injection, testing with testCheck/mockTarget, and registration.
---

# Writing Checks with CheckDefinitionV2

## Terminology

**"Check"** refers exclusively to the scan rule itself — the `defineCheckV2` definition with its metadata and `execute` function. Do not use "check" to name payloads, probes, test cases, or any internal data structures within a check. Use specific names instead: `payload`, `probe`, `pattern`, `testCase`, etc.

Bad: `TransformCheck`, `allChecks`, `currentCheckIndex`
Good: `TransformProbe`, `allProbes`, `currentProbeIndex`

## File Structure

A check doesn't have to be a single file. If the logic is complex, split it into modules within the check's own folder:

```
checks/my-check/
├── index.ts        # defineCheckV2 definition + execute function
├── index.spec.ts   # tests
├── probes.ts       # payload/probe definitions
└── utils.ts        # helper functions specific to this check
```

Keep `index.ts` focused on the check definition and orchestration. Move domain logic (probe generation, response analysis, etc.) into separate files.

## Overview

V2 checks are async functions that receive a `CheckContext` with utilities for sending requests, extracting parameters, emitting findings, and controlling iteration. No step-based state machine, no manual index tracking.

**Imports**: Everything comes from `"engine"`.

```ts
import { defineCheckV2, defineRegexCheck, Severity, ScanAggressivity, Result, keyStrategy } from "engine";
```

## defineCheckV2

Use for all checks (passive and active). Returns a `Check` compatible with the existing engine.

```ts
export default defineCheckV2({
  id: "my-check",
  name: "My Check",
  description: "Detects X vulnerability",
  type: "passive", // or "active"
  tags: ["tag1", "tag2"],
  severities: [Severity.MEDIUM],
  aggressivity: { minRequests: 0, maxRequests: 0 }, // passive: 0/0, active: set real bounds

  // Optional fields
  dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  when: (target) => target.response !== undefined,
  minAggressivity: ScanAggressivity.LOW,
  dependsOn: ["other-check-id"],
  skipIfFoundBy: ["other-check-id"],

  async execute(ctx) {
    // Check logic here
    // Optionally return output for dependent checks:
    // return { someData: "value" };
  },
});
```

## CheckContext API

The `ctx` object passed to `execute` provides:

### ctx.target (TargetAccessor)

Wraps the original `ScanTarget` with convenience methods:

| Method | Returns | Description |
|--------|---------|-------------|
| `ctx.target.request` | `Request` | The original request object |
| `ctx.target.response` | `Response \| undefined` | The original response object |
| `ctx.target.hasParameters()` | `boolean` | Has query params or body |
| `ctx.target.hasBody()` | `boolean` | Request has a body |
| `ctx.target.isMethod("POST", "PUT")` | `boolean` | Check request method (case-insensitive) |
| `ctx.target.header("content-type")` | `string \| undefined` | Get first response header value (case-insensitive) |
| `ctx.target.bodyText()` | `string \| undefined` | Get response body as text |

### ctx.parameters(opts?)

Extracts parameters from query string and request body (form/JSON). Handles content-type detection automatically.

```ts
const params = ctx.parameters();
const reflected = ctx.parameters({ reflected: true }); // Only params whose value appears in response body
```

Each `Parameter` has:
- `name: string`
- `value: string`
- `source: "query" | "body" | "header"`
- `inject(newValue: string): RequestSpec` — creates a new RequestSpec with that parameter replaced

### ctx.send(spec)

Sends an HTTP request. Returns `Result<SendOk, SendErr>`. Handles interruption automatically (throws on interrupt, no manual check needed).

```ts
const result = await ctx.send(spec);
if (Result.isErr(result)) return; // Request failed
const { request, response } = result.value;
```

### ctx.finding(input)

Emits a finding. Automatically uses the target request if `request` is not provided. Optional `impact`, `recommendation`, and `artifacts` fields are appended as markdown sections.

```ts
ctx.finding({
  name: "Vulnerability Found",
  severity: Severity.HIGH,
  description: "The parameter is vulnerable to X.",
  impact: "An attacker could...",           // optional, appended as ## Impact
  recommendation: "Sanitize input...",       // optional, appended as ## Recommendation
  artifacts: { title: "Payloads", items: ["payload1", "payload2"] }, // optional
  request: sentRequest,                      // optional, defaults to ctx.target.request
});
```

### ctx.limit(items, limits)

Slices an array based on scan aggressivity. Use for payload lists.

```ts
const payloads = ctx.limit(ALL_PAYLOADS, { low: 3, medium: 7, high: 13 });
```

### ctx.interrupted

Boolean flag. Check in long loops to bail early. Note: `ctx.send()` already handles interruption by throwing, so you only need this for CPU-bound loops that don't send requests.

### ctx.sdk, ctx.runtime, ctx.config

Full access to the Caido SDK, runtime utilities (HTML parsing, dependencies), and scan configuration. Same as V1's `RuntimeContext`.

## Result Type

`ctx.send()` returns `Result<SendOk, SendErr>`. Use the helpers:

```ts
Result.isOk(result)  // Type guard for { kind: "Ok", value: SendOk }
Result.isErr(result) // Type guard for { kind: "Error", error: SendErr }
```

## defineRegexCheck

Shortcut for passive checks that match regex patterns against response bodies. No `execute` needed.

```ts
export default defineRegexCheck({
  id: "my-regex-check",
  name: "Pattern Disclosure",
  description: "Detects sensitive patterns in responses",
  tags: ["disclosure"],
  severity: Severity.LOW,
  patterns: [/pattern1/i, /pattern2/i],
  dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  when: (target) => target.response !== undefined,
  toFinding: (matches) => ({
    name: "Sensitive Pattern Found",
    description: `Found: ${matches.join(", ")}`,
  }),
});
```

## Patterns

### Passive check (inspect response only)

```ts
export default defineCheckV2({
  id: "missing-header",
  name: "Missing Security Header",
  description: "Detects missing X-Frame-Options header",
  type: "passive",
  tags: ["security-headers"],
  severities: [Severity.INFO],
  aggressivity: { minRequests: 0, maxRequests: 0 },
  dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  when: (target) => target.response !== undefined,

  async execute(ctx) {
    const header = ctx.target.header("x-frame-options");
    if (header !== undefined) return;

    ctx.finding({
      name: "Missing X-Frame-Options",
      severity: Severity.INFO,
      description: "Response is missing the X-Frame-Options header.",
      recommendation: "Add X-Frame-Options header with DENY or SAMEORIGIN.",
    });
  },
});
```

### Active check (send requests with parameter injection)

```ts
export default defineCheckV2({
  id: "my-injection",
  name: "Injection Check",
  description: "Tests parameters for injection",
  type: "active",
  tags: ["injection"],
  severities: [Severity.HIGH],
  aggressivity: { minRequests: 1, maxRequests: "Infinity" },
  dedupeKey: keyStrategy().withMethod().withHost().withPort().withPath().withQueryKeys().build(),
  when: (target) => target.response !== undefined,

  async execute(ctx) {
    if (!ctx.target.hasParameters()) return;

    const params = ctx.parameters();
    const payloads = ctx.limit(ALL_PAYLOADS, { low: 3, medium: 7, high: 13 });

    for (const param of params) {
      for (const payload of payloads) {
        const spec = param.inject(param.value + payload.value);
        const result = await ctx.send(spec);
        if (Result.isErr(result)) continue;

        const { request, response } = result.value;
        const body = response.getBody()?.toText();
        if (body !== undefined && payload.pattern.test(body)) {
          ctx.finding({
            name: `Injection in '${param.name}'`,
            severity: Severity.HIGH,
            description: `Parameter \`${param.name}\` is vulnerable.`,
            request,
          });
          return;
        }
      }
    }
  },
});
```

### Active check (send custom requests, not parameter-based)

```ts
export default defineCheckV2({
  id: "endpoint-probe",
  name: "Endpoint Probe",
  description: "Probes for sensitive endpoints",
  type: "active",
  tags: ["discovery"],
  severities: [Severity.MEDIUM],
  aggressivity: { minRequests: 1, maxRequests: 5 },
  dedupeKey: keyStrategy().withHost().withPort().withBasePath().build(),

  async execute(ctx) {
    const paths = ctx.limit(["/admin", "/.env", "/debug"], { low: 1, medium: 2, high: 3 });

    for (const path of paths) {
      const spec = ctx.target.request.toSpec();
      spec.setPath(path);
      const result = await ctx.send(spec);
      if (Result.isErr(result)) continue;

      if (result.value.response.getCode() === 200) {
        ctx.finding({
          name: `Sensitive endpoint: ${path}`,
          severity: Severity.MEDIUM,
          description: `Endpoint \`${path}\` returned 200 OK.`,
          request: result.value.request,
        });
      }
    }
  },
});
```

## Testing

Use `testCheck`, `testChecks`, and `mockTarget` from `"engine"`. Tests use vitest.

```ts
import { mockTarget, testCheck, Severity } from "engine";
import { describe, expect, it } from "vitest";

import myCheck from "./index";

describe("My Check", () => {
  it("should detect vulnerability", async () => {
    const target = mockTarget({
      request: { id: "1", host: "example.com", method: "GET", path: "/page" },
      response: { id: "1", code: 200, headers: {}, body: "vulnerable content" },
    });

    const { findings } = await testCheck(myCheck, target);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      name: "Expected Finding",
      severity: "medium",
    });
  });

  it("should not produce findings for safe response", async () => {
    const target = mockTarget({
      request: { id: "2", host: "example.com", method: "GET", path: "/safe" },
      response: { id: "2", code: 200, headers: {}, body: "safe content" },
    });

    const { findings } = await testCheck(myCheck, target);

    expect(findings).toHaveLength(0);
  });
});
```

### Testing active checks (with sendHandler)

```ts
it("should detect injection via sent request", async () => {
  const target = mockTarget({
    request: { id: "1", host: "example.com", method: "POST", path: "/api", body: "user=admin" },
    response: { id: "1", code: 200, headers: { "Content-Type": ["application/x-www-form-urlencoded"] } },
  });

  const { findings } = await testCheck(myCheck, target, {
    sendHandler: async (spec) => {
      const body = spec.getBody()?.toText() ?? "";
      return {
        request: mockTarget({ request: { id: "sent-1", host: "example.com" } }).request,
        response: mockTarget({
          request: { id: "sent-1", host: "example.com" },
          response: { id: "sent-1", code: 200, body: body.includes("payload") ? "vulnerable" : "safe" },
        }).response!,
      };
    },
  });

  expect(findings).toHaveLength(1);
});
```

### mockTarget options

```ts
mockTarget({
  request: {
    id: string;          // required
    host: string;        // required
    method?: string;     // default: "GET"
    path?: string;       // default: "/"
    query?: string;      // default: ""
    headers?: Record<string, string[]>;
    body?: string;
    port?: number;
    tls?: boolean;
  },
  response?: {           // omit for no response
    id: string;          // required
    code: number;        // required
    headers?: Record<string, string[]>;
    body?: string;
  },
});
```

## Registration

After creating the check file at `packages/backend/src/checks/<check-name>/index.ts`:

1. Import and add to `packages/backend/src/checks/index.ts`:

```ts
import myCheckScan from "./my-check";

export const Checks = {
  // ... existing
  MY_CHECK: "my-check",
};

export const checks = [
  // ... existing
  myCheckScan,
];
```

2. Add to presets in `packages/backend/src/stores/presets/`:
   - **Light**: passive only if zero requests; active only if very few requests
   - **Balanced**: usually enable in active; passive only if lightweight
   - **Bug Bounty**: active usually yes; passive only if high-value finding
   - **Heavy**: all checks enabled by default, no changes needed

## keyStrategy

Builder for deduplication keys. Chain methods and call `.build()`:

```ts
keyStrategy().withHost().withPort().withPath().build()
keyStrategy().withMethod().withHost().withPort().withPath().withQueryKeys().build()
```

Available: `withHost()`, `withPort()`, `withPath()`, `withBasePath()`, `withMethod()`, `withQuery()`, `withQueryKeys()`.

## Checklist

- [ ] `id` is unique kebab-case
- [ ] `type` is `"passive"` (no requests sent) or `"active"` (sends requests)
- [ ] `severities` array matches what `ctx.finding()` actually emits
- [ ] `aggressivity` is `{ minRequests: 0, maxRequests: 0 }` for passive
- [ ] `dedupeKey` set to avoid duplicate runs on same target
- [ ] `when` filters out irrelevant targets early
- [ ] Active checks use `ctx.limit()` for payload lists
- [ ] `Result.isErr()` checked after every `ctx.send()`
- [ ] Tests cover: finding produced, no finding on safe input, `when` filtering
- [ ] Registered in `checks/index.ts` and added to presets
