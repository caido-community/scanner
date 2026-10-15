<div align="center">
  <img width="1000" alt="image" src="docs/banner.png">

  <br />
  <br />
  <a href="https://github.com/caido-community" target="_blank">Github</a>
  <span>&nbsp;&nbsp;•&nbsp;&nbsp;</span>
  <a href="https://developer.caido.io/" target="_blank">Documentation</a>
  <span>&nbsp;&nbsp;•&nbsp;&nbsp;</span>
  <a href="https://links.caido.io/www-discord" target="_blank">Discord</a>
  <br />
  <hr />
</div>

# Scanner

A web vulnerability scanner plugin for Caido.

### About Scanner

Scanner is a vulnerability detection plugin that brings automated security testing capabilities to Caido. Scanner provides a user-friendly interface for identifying common web application vulnerabilities.

<video src="docs/demo.mp4" controls preload></video>

## 🚀 Getting Started

### Installation [Recommended]

1. Open Caido, navigate to the `Plugins` sidebar page and then to the `Community Store` tab
2. Find `Scanner` and click Install
3. Done! 🎉

### Installation [Manual]

1. Go to the [Scanner Releases tab](https://github.com/caido-community/scanner/releases) and download the latest `plugin_package.zip` file
2. In your Caido instance, navigate to the `Plugins` page, click `Install` and select the downloaded `plugin_package.zip` file
3. Done! 🎉

## 💚 Community

Join our [Discord](https://links.caido.io/www-discord) community and connect with other Caido users! Share your ideas, ask questions, and get involved in discussions around Caido and security testing.

## 🧑‍💻 Developer Documentation

### Scanner Structure

The project is organized into distinct packages: `backend`, `frontend`, `engine`, and `shared`. The `engine` package is responsible for all the logic related to executing checks. All checks are located within the `packages/backend/src/checks/` directory.

### Check Definition

To define your own check, use the `defineCheck` function as shown below. The check metadata contains static information about the check, some fields, such as `id`, are always required, while others are used for filtering.

```ts
import { defineCheck, Severity } from "engine";
import { keyStrategy } from "../../utils/key";


export const exampleCheck = defineCheck(({ step }) => {
  return {
    metadata: {
      id: "example-check",
      name: "Example Check",
      description:
        "This is an example check",
      type: "passive",
      tags: ["example"],
      severities: [Severity.INFO],
      aggressivity: {
        minRequests: 0,
        maxRequests: 0,
      },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: (context) => {
      return (
        context.response !== undefined && context.response.getCode() === 200
      );
    },
  };
});
```

### Check Metadata

The `CheckMetadata` type is a crucial part of defining a check, as it contains all the static information about the check. Here's a breakdown of its components:

- **id**: A unique identifier for the check. This is required and ensures that each check can be distinctly referenced.
- **name**: A human-readable name for the check, which is displayed in the UI.
- **description**: A detailed explanation of what the check does and the vulnerabilities it detects. This helps users understand the check's functionality and scope.
- **tags**: An array of tags used for categorization and filtering. Tags help in organizing checks and making them easily searchable.
- **aggressivity**: This defines the request limits for the check. It uses the `CheckAggressivity` type, which specifies `minRequests` and `maxRequests`. If the request count is dynamic, use `Infinity` for `maxRequests`.
- **type**: Indicates whether the check is `passive` or `active`. This helps in determining how the check interacts with the target. Use `passive` if the scan is silent enough to run in the background without causing noise, and `active` if the scan requires more noticeable interaction with the target.
- **severities**: An array of possible severity levels that the check can report. This is used for filtering, and the engine will throw an error if a finding is returned with a severity not included in this array.
- **dependsOn** (optional): An array of check IDs that must run before this check. This ensures that dependencies are resolved before execution.
- **minAggressivity** (optional): The minimum scan aggressivity level required for this check to run. This allows checks to be gated by the scan's aggressivity level.
- **skipIfFoundBy** (optional): An array of check IDs. If any of these checks have found findings during the scan, this check will be skipped.

```ts
export type CheckAggressivity = {
  minRequests: number;
  maxRequests: number | "Infinity";
};

export type CheckType = "passive" | "active";
export type CheckMetadata = {
  /** Unique identifier for the check */
  id: string;
  /** Human-readable name displayed in the UI */
  name: string;
  /** Detailed description of what the check does and what vulnerabilities it detects */
  description: string;
  /** Array of tags used for categorization and filtering */
  tags: string[];
  /** Defines the request limits for this check. Please use Infinity if it's dynamic. */
  aggressivity: CheckAggressivity;
  /** Whether this is a passive or active check */
  type: CheckType;
  /**
   * Array of possible severity levels this check can report.
   * This is used for filtering.
   * Engine will throw an error if you return a finding with a severity that is not in this array.
   **/
  severities: Severity[];
  /** Optional: Array of check IDs that must run before this check */
  dependsOn?: string[];
  /** Optional: Minimum scan aggressivity level required for this check to run */
  minAggressivity?: ScanAggressivity;
  /** Optional: array of check IDs - if any of these check IDs have found any findings during the scan, skip this check */
  skipIfFoundBy?: string[];
};
```

### Steps

Steps let you break your check into smaller parts. Each step should be simple and quick. End a step with `done(...)` or go to the next step with `continueWith({ state, nextStep: '...' })`.

```ts
import { continueWith, defineCheck, done, Severity } from "engine";

export default defineCheck<{
  responseBody: string | undefined;
}>(({ step }) => {
  step("check200", async (state, context) => {
    if (
      context.target.response !== undefined &&
      context.target.response.getCode() === 200
    ) {
      const responseBody = context.target.response.getBody()?.toText();

      return continueWith({
        state: {
          responseBody,
        },
        nextStep: "reportFinding",
      });
    }
    return done({ state });
  });

  step("reportFinding", async (state, context) => {
    const finding = {
      name: "HTTP 200 OK",
      description: `Target responded with 200 OK. Response body: ${state.responseBody}`,
      severity: Severity.INFO,
      correlation: {
        requestID: context.target.request.getId(),
        locations: [],
      },
    };
    return done({ state, findings: [finding] });
  });

  return {
    metadata: {
      id: "example-check",
      name: "Example Check",
      description: "This is an example check",
      type: "passive",
      tags: ["example"],
      severities: [Severity.INFO],
      aggressivity: {
        minRequests: 0,
        maxRequests: 0,
      },
    },
    dedupeKey: (context) =>
      context.request.getHost() +
      context.request.getPort() +
      context.request.getPath(),
    when: (context) => context.response !== undefined,
    initState: () => ({
      responseBody: undefined,
    }),
  };
});
```

State allows you to pass data from one step to another within your check. When you define a state for your check, you must also provide an `initState` function in your return statement that sets the initial value for your state. Context gives you access to the Caido Backend SDK, the scanner engine runtime SDK (which will be explained later), as well as the target request and response.

### Checks Engine

The checks engine is built around a step-based execution model that allows responsive and interruptible scans. Each check is composed of sequential steps that can pass data through state, send requests, and produce findings.

### Steps

Steps are the fundamental building blocks of a check in the engine. Steps are executed sequentially, and each execution of a step is called a "tick".

Keeping each tick short is important. After every tick, the engine checks if the scan has been aborted. If a step were to perform multiple long-running actions (like sending several requests in a loop), the user would have to wait for all of them to finish. By designing checks so that each step only sends one request or performs a small piece of logic, we ensure that the engine remains responsive and can quickly react to user actions or scan interruptions.

When you need to perform multiple actions (such as sending several requests), structure your check so that each action happens in its own step. This way, each tick is short, and the engine can efficiently manage scan flow and user interactions.

A common pattern in checks is to create loops by reusing the same step in `nextStep`. This allows you to perform iterative operations like testing multiple paths or parameters. Once your loop condition is met, you can either return `done()` to complete the check or `continue()` to proceed to subsequent steps.

### Context

Context provides access to:

- The Caido Backend SDK via the `sdk` field
- The request and response of the scan target via the `target` field
- The Runtime SDK via the `runtime` field
- The scan configuration via the `config` field

### Runtime SDK

The runtime SDK is a set of utilities specifically scoped to the current scan.

```ts
/** Runtime SDK for accessing utilities scoped to the current scan. */
runtime: {
  /** Utilities for parsing HTML. */
  html: {
    /** Parse the HTML of a request. This returns a ParsedHtml which has DOM-like methods for querying the HTML. */
    parse: (requestID: string) => Promise<ParsedHtml>;
  };
  /** Access to the dependencies of the check. */
  dependencies: {
    /** Get a dependency by key. */
    get: (key: string) => JSONSerializable | undefined;
  };
};
```

### Dependencies

Use dependencies to pass outputs from one check to another.

- Declare upstream check IDs in `metadata.dependsOn`. The engine orders checks so dependencies always finish before dependents run.
- Produce data from a check using `output({ state, context })`.
- Read dependency values in another check via `context.runtime.dependencies.get('<check-id>')`.

Example: provider check that exposes an output

```ts
import { defineCheck, Severity } from "engine";

export const helloWorldProvider = defineCheck(({ step }) => {
  return {
    metadata: {
      id: "example-output",
      name: "Example Output Provider",
      description: "Produces a simple string output",
      type: "passive",
      tags: ["example"],
      severities: [Severity.INFO],
      aggressivity: {
        minRequests: 0,
        maxRequests: 0,
      },
    },
    // Notice output being used here
    output: ({ state, context }) => {
      return "Hello world!";
    },
    initState: () => ({}),
    dedupeKey: (context) => {
      return (
        context.request.getHost() +
        context.request.getPort() +
        context.request.getPath()
      );
    },
    when: (context) => {
      return (
        context.response !== undefined && context.response.getCode() === 200
      );
    },
  };
});
```

Example: consumer check that depends on the provider

```ts
import { defineCheck, done, Severity } from "engine";

export const helloWorldConsumer = defineCheck(({ step }) => {
  step("example-step", async (state, context) => {
    const dependency = context.runtime.dependencies.get(
      "example-output"
    ) as string;
    console.log(dependency); // "Hello world!"

    return done({ state });
  });

  return {
    metadata: {
      id: "example-consumer",
      name: "Example Consumer",
      description: "Consumes output from example-output",
      type: "passive",
      tags: ["example"],
      severities: [Severity.INFO],
      aggressivity: {
        minRequests: 0,
        maxRequests: 0,
      },
      // Notice "example-output" being used in dependsOn, engine will always make sure to run it first
      dependsOn: ["example-output"],
    },
    initState: () => ({}),
    dedupeKey: (context) => {
      return (
        context.request.getHost() +
        context.request.getPort() +
        context.request.getPath()
      );
    },
    when: (context) => {
      return (
        context.response !== undefined && context.response.getCode() === 200
      );
    },
  };
});
```

#### Notes

- Outputs are stored per check ID and made available to later checks.
- Outputs must be JSON‑serializable. Keep them small and focused.

## Utilities

The engine provides helper utilities you can use inside checks. Two commonly used ones are redirection detection and URL bypass payload generation.

```ts
import { createUrlBypassGenerator, findRedirection } from "engine";
```

### Redirection detection

Detects whether a response leads to a redirect and extracts its destination. It covers HTTP 3xx with Location header, Refresh header, HTML meta refresh/location, base tag, and JavaScript-based redirects.

```ts
async function findRedirection(
  requestID: string,
  context: RuntimeContext,
): Promise<RedirectionInfo>
```

```ts
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
```

### URL bypass payload generator

Generates a sequence of URL payload recipes that attempt to bypass naive allowlists. Each recipe can produce a payload string value and validate that a resulting redirect points to the attacker host. You can filter techniques or limit the number of generated recipes.

```ts
function createUrlBypassGenerator(input: {
  expectedHost: string;
  attackerHost: string;
  originalValue?: string;
  protocol?: string;
}): UrlBypassGenerator
```

Filter or cap techniques:

```ts
const generator = createUrlBypassGenerator({
  expectedHost: "example.com",
  attackerHost: "attacker.test",
}).only("UserInfoBypass", "SchemeRelative");
```

#### Example: iterate payloads and validate a redirect

```ts
import { defineCheck, done, Severity, createUrlBypassGenerator, findRedirection } from "engine";

export default defineCheck(({ step }) => {
  step("testOpenRedirect", async (state, context) => {
    const currentParam = "redirect";

    const generator = createUrlBypassGenerator({
      expectedHost: context.target.request.getHost(),
      attackerHost: "attacker.com",
      protocol: "https:",
    });

    for (const payloadRecipe of generator) {
      const payload = payloadRecipe.generate();

      const params = new URLSearchParams(context.target.request.getQuery());
      params.set(currentParam, payload.value);

      const spec = context.target.request.toSpec();
      spec.setQuery(params.toString());

      const { request } = await context.sdk.requests.send(spec);
      const redirectInfo = await findRedirection(request.getId(), context);

      if (redirectInfo.hasRedirection) {
        const redirectUrl = new URL(
          redirectInfo.location,
          context.target.request.getUrl(),
        );

        if (payload.validatesWith(redirectUrl)) {
          return done({
            state,
            findings: [
              {
                name: `Open Redirect in parameter '${currentParam}'`,
                description: "Target redirected to an external domain.",
                severity: Severity.MEDIUM,
                correlation: {
                  requestID: request.getId(),
                  locations: [],
                },
              },
            ],
          });
        }
      }
    }

    return done({ state });
  });

  return {
    metadata: {
      id: "example-open-redirect",
      name: "Example Open Redirect",
      description: "Demonstrates using utilities to find open redirects",
      type: "active",
      tags: ["open-redirect"],
      severities: [Severity.MEDIUM],
      aggressivity: { minRequests: 0, maxRequests: "Infinity" },
    },
    initState: () => ({}),
    dedupeKey: (context) =>
      context.request.getHost() +
      context.request.getPort() +
      context.request.getPath(),
  };
});
```

## 🤝 Contributing

Feel free to contribute! If you'd like to request a feature or report a bug, please create a [GitHub Issue](https://github.com/caido-community/scanner/issues/new).

### Ways to Contribute

- Report bugs and request features via GitHub Issues.
- Improve docs and examples.
- Add new vulnerability checks.

### Add a New Check

> [!NOTE]
> All checks live in `packages/backend/src/checks`. Each check uses a folder with two files: `index.ts` and `index.spec.ts`. As the logic gets more complicated, you can spread it into multiple files within the same folder.

#### 1) Scaffold

Create a new folder and add your implementation and tests:

```text
packages/backend/src/checks/
  ├─ my-check/
  │  ├─ index.ts
  │  └─ index.spec.ts
```

Follow the check patterns in the existing checks. Implement your check with the engine step model and add unit tests in `index.spec.ts`.

#### 2) Register the Check

Open `packages/backend/src/checks/index.ts` and:

- Add an import for your check
- Add a new entry to `Checks`
- Append your check to the `checks` array

```ts
import myCheckScan from "./my-check";

export const Checks = {
  // ...
  MY_CHECK: "my-check",
} as const;

export const checks = [
  // ...
  myCheckScan,
] as const;
```

#### 3) Add to Presets

Open `packages/backend/src/stores/config.ts` and include your check in default presets. Always add it to the Heavy preset as enabled. Depending on aggressivity and type, you may also add it to Light or Balanced.

Decide whether your check belongs to `active` or `passive` based on `metadata.type` in your check.

```ts
{
  name: "Heavy",
  active: [
    // ...
    { checkID: Checks.MY_CHECK, enabled: true },
  ],
  passive: [
    // ...
  ],
}
```

#### 4) Validate Locally

Run formatting, types, tests, and a build from the repo root:

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```
