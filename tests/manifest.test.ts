import { readFileSync } from "node:fs";
import { parseManifest } from "@docleus/sdk";
import { describe, expect, it } from "vitest";
import config from "../tsdown.config.ts";
import { PLUGIN_NAME } from "../src/server/index.ts";

const manifest = parseManifest(
  JSON.parse(
    readFileSync(new URL("../docleus.plugin.json", import.meta.url), "utf8"),
  ),
);

describe("docleus.plugin.json", () => {
  it("names the plugin and has only a server entry", () => {
    expect(manifest.name).toBe(PLUGIN_NAME);
    expect(manifest.entries).toEqual({ server: "./dist/server/index.js" });
  });

  it("points at the file the build produces", () => {
    const build = config as { entry?: Record<string, string> };
    const outputs = Object.keys(build.entry ?? {}).map(
      (name) => `./dist/${name}.js`,
    );
    expect(outputs).toContain(manifest.entries.server);
  });
});
