import { definePlugin } from "@docleus/sdk";
import { parseOidcConfig } from "./config.ts";
import { PLUGIN_NAME } from "./name.ts";
import { registerOidc, type OidcOptions } from "./oidc.ts";

export {
  DEFAULT_SCOPES,
  parseOidcConfig,
  type OidcConfig,
  type OidcSource,
  type SignupPolicy,
} from "./config.ts";
export {
  callbackPath,
  isSafeReturnPath,
  providerId,
  startPath,
  type OidcLoginError,
  type OidcOptions,
} from "./oidc.ts";
export { PENDING_LOGIN_TTL_MS } from "./pending.ts";
export { PLUGIN_NAME } from "./name.ts";

/**
 * Builds the plugin. `options` exist for tests; the host loads {@link plugin}.
 * The config is validated when the plugin applies and an invalid one fails
 * with `oidc/invalid-config`.
 */
export function createOidcPlugin(options: OidcOptions = {}) {
  return definePlugin({
    name: PLUGIN_NAME,
    inject: ["identity", "http", "storage"],
    apply(ctx, config: unknown) {
      registerOidc(ctx, parseOidcConfig(config), options);
    },
  });
}

/** Sign-in through the OpenID Connect providers listed in the config. */
export const plugin = createOidcPlugin();
