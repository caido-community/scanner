import { defaultConfig } from "@caido/eslint-config";

export default [
  {
    ignores: ["**/__generated__.*"],
  },
  ...defaultConfig({
    compat: false,
  }),
];
