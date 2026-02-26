# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
pnpm run build            # Build the plugin
pnpm run watch            # Build with watch mode
pnpm run lint             # ESLint with auto-fix
pnpm run typecheck        # TypeScript type checking
pnpm run test             # Run all tests (vitest)
pnpm run validate         # Run typecheck + lint + test
pnpm vitest run packages/backend/src/checks/<check-name>/index.spec.ts  # Run a single test file
pnpm vitest run --coverage  # Run tests with code coverage report
pnpm vitest run --coverage packages/backend/src/checks/<check-name>/index.spec.ts  # Coverage for a specific check
lint-dev                  # Custom Caido linting (available in $PATH)
```

## Architecture

This is a **Caido vulnerability scanner plugin** organized as a pnpm monorepo with four packages:

- **`packages/engine`** — Core scanning engine. Defines the check execution model (step-based), types (`CheckDefinition`, `Finding`, `Severity`), and test utilities (`runCheck`, `createMockRequest`, `createMockResponse`). Imported as `"engine"` by other packages.
- **`packages/backend`** — Backend plugin. Contains 40+ vulnerability checks in `src/checks/`, plus services, stores, and storage layers. Registers API endpoints and hooks into Caido SDK events (intercepted responses for passive scanning, `sdk.requests.send()` for active scanning).
- **`packages/frontend`** — Vue 3 + Pinia + PrimeVue + TailwindCSS frontend. Registers a sidebar page at `/scanner` and a keyboard shortcut (Ctrl+Shift+S) for active scanning.
- **`packages/shared`** — Shared TypeScript types between frontend and backend.

Plugin configuration lives in `caido.config.ts`. The plugin is built using `@caido-community/dev`.

## Check Architecture

Checks use a **step-based execution model**. Each check defines metadata, an initial state, a `when` condition, a `dedupeKey`, and one or more steps. Steps either `done()` or `continueWith()` to the next step.

**Two APIs exist:** `defineCheck` (step-based with explicit state machine) and `defineCheckV2` (simplified, single `execute` function with `ctx.parameters()`, `ctx.send()`, `ctx.finding()`). Study existing checks in `packages/backend/src/checks/` before writing new ones.

### Adding a New Check

1. Create `packages/backend/src/checks/<check-name>/index.ts` and `index.spec.ts`
2. Register in `packages/backend/src/checks/index.ts`
3. Add to presets in `packages/backend/src/stores/presets/` (Light, Balanced, BugBounty, Heavy)

### Testing Checks

Use `runCheck` from engine. Two distinct scenarios:
- Check doesn't run (`when` returns false) → execution history is `[]`
- Check runs but finds nothing → execution history is non-empty with empty findings

Test both positive cases (vulnerability detected) and negative cases (safe input).

## Code Conventions

- **TypeScript only.** Use `type`, not `interface`. Never use `any`.
- **Use `undefined` over `null`.**
- **No comments** in generated code.
- **Explicit nullish checks:** `if (str !== undefined)` not `if (!str)` — the linter enforces this for nullable strings.
- **Naming:** folders are camelCase, component folders are PascalCase, files are camelCase.
- **Declare variables close to usage**, not at the top of functions.
- **No alias types** — rename and fix all occurrences instead.

## Frontend Conventions

- **Vue 3** with `<script setup lang="ts">`. Use PrimeVue components.
- **Props/emits:** inline type definitions in `defineProps<>` and `defineEmits<>` (no separate type).
- **Destructure props** with `toRefs`.
- **Styling:** TailwindCSS only. Dark mode default. `bg-surface-800` for app background, `bg-surface-700` for cards. Prefer `...-surface-...` color classes.
- **Conditional classes:** prefer `:class="{ ... }"` Vue syntax.

## Store Conventions (Pinia)

Stores use the setup API with this file structure:
- `index.ts` — public store combining composables, always exposes `reset()`
- `useState.ts` — private state using `definePrivateStore`, contains the `State` type
- `use[Feature].ts` — composables with business logic, return getters/setters (never expose refs directly)
- `use[Feature].spec.ts` — tests

Store IDs follow the format `stores.[feature-name]`.

## Testing Philosophy

Focus on behavior, not implementation. When a test fails, determine if it's a check issue or a test issue — fix the check if it has bugs, don't adjust tests to pass broken behavior.
