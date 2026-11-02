import { defineConfig } from "tsdown";

export default defineConfig({
  entry: { "server/index": "src/server/index.ts" },
  format: "esm",
  dts: false,
  outExtensions: () => ({ js: ".js" }),
  clean: true,
});
