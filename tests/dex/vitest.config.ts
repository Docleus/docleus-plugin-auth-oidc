import { defineConfig } from "vitest/config";

// Not built on baseVitestConfig: its type comes from core's copy of vitest,
// which tsc treats as distinct from this repository's copy.
export default defineConfig({
  test: {
    include: ["tests/dex/**/*.acceptance.ts"],
    environment: "node",
    testTimeout: 60_000,
    hookTimeout: 120_000,
  },
});
