import type { RawConfigurationOrFn } from "knip/dist/types/config.js";

const config: RawConfigurationOrFn = {
  workspaces: {
    ".": {
      entry: ["caido.config.ts"],
      ignoreDependencies: ["@caido/sdk-backend", "@vitest/coverage-v8", "rollup-plugin-dts"],
    },
    "packages/backend": {
      project: ["src/**/*.ts"],
      ignoreDependencies: ["caido", "@lezer/common", "@lezer/generator"],
      ignore: [
        "src/parsers/**/__generated__*",
        "src/checks/sql-injection/mysql-time-based/**",
      ],
    },
    "packages/frontend": {
      project: ["src/**/*.{ts,tsx,vue}"],
      ignore: [
        "src/views/Queue.vue",
        "src/components/queue/**",
        "src/types/queue.ts",
      ],
    },
    "packages/shared": {
      project: ["src/**/*.ts"],
    },
    "packages/engine": {
      project: ["src/**/*.ts"],
      ignoreDependencies: ["caido"],
      ignore: ["src/__tests__/**"],
    },
    "packages/trace-viewer": {
      project: ["src/**/*.{ts,vue}"],
      ignoreDependencies: ["postcss", "@fortawesome/fontawesome-free"],
    },
  },
};

export default config;
