import { defineConfig } from "tsdown";

export default defineConfig({
  entry: ["./src/index.ts"],
  platform: "node",
  format: "esm",
  dts: true,
  sourcemap: true,
  clean: true,
  deps: {
    neverBundle: ["@caido/sdk-shared"],
  },
});
