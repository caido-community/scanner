import type { RawConfigurationOrFn } from "knip/dist/types/config.js";

const config: RawConfigurationOrFn = {
  workspaces: {
    ".": {
      entry: ["caido.config.ts"],
      ignoreDependencies: ["@vitest/coverage-v8", "rollup-plugin-dts"],
    },
    "packages/backend": {
      project: ["src/**/*.ts"],
      ignoreDependencies: [
        "caido",
        "shared",
        "@lezer/common",
        "@lezer/generator",
      ],
      ignore: [
        "src/parsers/**/__generated__*",
        "src/checks/sql-injection/mysql-time-based/**",
      ],
    },
    "packages/frontend": {
      project: ["src/**/*.{ts,tsx,vue}"],
      ignoreDependencies: ["shared"],
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
      ignoreDependencies: ["caido", "shared"],
      ignore: ["src/__tests__/**"],
    },
    "packages/trace-viewer": {
      project: ["src/**/*.{ts,vue}"],
      ignoreDependencies: ["postcss", "@fortawesome/fontawesome-free"],
    },
  },
};

export default config;
