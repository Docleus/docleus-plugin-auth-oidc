/** @type {import('dependency-cruiser').IConfiguration} */
module.exports = {
  forbidden: [
    {
      name: "no-circular",
      severity: "error",
      from: {},
      to: { circular: true },
    },
    {
      name: "plugins-use-sdk-only",
      severity: "error",
      comment:
        "Plugins depend on @docleus/sdk, never on core internals or other plugins.",
      from: { path: "^src" },
      to: { path: "node_modules/@docleus/(?!sdk/|config/)" },
    },
  ],
  options: {
    doNotFollow: { path: "node_modules" },
    tsPreCompilationDeps: true,
    tsConfig: { fileName: "tsconfig.json" },
  },
};
