import { createAuthzService } from "@docleus/core-authz";
import { createHttpService } from "@docleus/core-http";
import { createIdentityService } from "@docleus/core-identity";
import { createStorageService } from "@docleus/core-storage";
import { Context, SESSION_COOKIE, type StorageService } from "@docleus/sdk";
import { testStorageLocation } from "@docleus/testing";
import { createOidcPlugin, type OidcOptions } from "../src/server/index.ts";

export const ORIGIN = "http://docleus.test";

export interface Instance {
  readonly root: Context;
  /** Messages logged at `warn` or above, formatted. */
  readonly warnings: string[];
  fetch(path: string, init?: RequestInit): Promise<Response>;
  unloadPlugin(): Promise<void>;
  dispose(): Promise<void>;
}

/**
 * The core services the plugin needs, the plugin with `config`, and a
 * signed-in-only `GET /api/test/me` route that answers with the user id.
 * Given `storage`, the instance uses it instead of its own, like a second
 * web process on the same database.
 */
export async function loadPlugin(
  config: unknown,
  options: OidcOptions = {},
  storage?: StorageService,
): Promise<Instance> {
  const root = new Context();
  const warnings: string[] = [];
  root.logger.exporter({
    export(message) {
      if (message.type !== "warn" && message.type !== "error") return;
      const [format, ...args] = message.args as [unknown, ...unknown[]];
      let index = 0;
      warnings.push(
        String(format).replace(/%[sdo]/g, () => String(args[index++])),
      );
    },
  });
  const storageLocation =
    storage === undefined ? await testStorageLocation() : undefined;
  const core = await root.plugin((ctx: Context) => {
    ctx.provide(
      "storage",
      storage ?? createStorageService(ctx, storageLocation),
    );
    ctx.provide("identity", createIdentityService(ctx));
    ctx.provide("authz", createAuthzService(ctx));
    ctx.provide("http", createHttpService(ctx));
  });
  const routes = await root.plugin({
    name: "test-routes",
    inject: ["http"],
    apply(ctx: Context) {
      ctx.http.route("GET", "/api/test/me", ({ actor }) =>
        Response.json({ userId: actor.kind === "user" ? actor.userId : null }),
      );
    },
  });
  let fiber: Awaited<ReturnType<Context["plugin"]>>;
  try {
    fiber = await root.plugin(createOidcPlugin(options), config as never);
  } catch (error) {
    // Otherwise the open storage connection outlives the failed load.
    await routes.dispose();
    await core.dispose();
    throw error;
  }
  return {
    root,
    warnings,
    fetch: (path, init) =>
      root.http.fetch(new Request(new URL(path, ORIGIN), init)),
    unloadPlugin: () => fiber.dispose(),
    async dispose() {
      await fiber.dispose();
      await routes.dispose();
      await core.dispose();
    },
  };
}

/** The session token in a `Set-Cookie` value, or undefined when it ends the session. */
export function sessionToken(setCookie: string | null): string | undefined {
  const match = new RegExp(`^${SESSION_COOKIE}=([^;]*)`).exec(setCookie ?? "");
  return match?.[1] === undefined || match[1] === "" ? undefined : match[1];
}
