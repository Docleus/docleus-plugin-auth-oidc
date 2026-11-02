import { z, type Context } from "@docleus/sdk";
import {
  allowInsecureRequests,
  authorizationCodeGrant,
  buildAuthorizationUrl,
  calculatePKCECodeChallenge,
  discovery,
  None,
  randomNonce,
  randomPKCECodeVerifier,
  randomState,
  type Configuration,
} from "openid-client";
import type { OidcConfig, OidcSource } from "./config.ts";
import { PLUGIN_NAME } from "./name.ts";
import { createPendingLogins, type PendingLogin } from "./pending.ts";

export interface OidcOptions {
  /** Clock for pending-login expiry; `Date.now` by default. */
  readonly now?: () => number;
}

/** The error codes the sign-in page receives in `?error=`. */
export type OidcLoginError =
  "oidc-failed" | "oidc-signup-required" | "oidc-email-unverified";

const SWEEP_INTERVAL_MS = 60 * 1000;
const MAX_PARAM_LENGTH = 2048;

export const providerId = (source: OidcSource): string => `oidc.${source.id}`;
export const startPath = (source: OidcSource): string =>
  `/api/auth/oidc/${source.id}/start`;
export const callbackPath = (source: OidcSource): string =>
  `/api/auth/oidc/${source.id}/callback`;

/** A path on this origin: `/...`, but not `//host` or `/\host`, which browsers treat as another origin. */
export function isSafeReturnPath(value: string): boolean {
  if (value.length > MAX_PARAM_LENGTH) return false;
  if (!value.startsWith("/") || value.startsWith("//")) return false;
  if (value.startsWith("/\\")) return false;
  // oxlint-disable-next-line no-control-regex -- control characters are exactly what is rejected here.
  if (/[\u0000-\u001f\u007f]/.test(value)) return false;
  const base = "http://return.invalid";
  return new URL(value, base).origin === base;
}

function jsonError(status: number, code: string, message: string): Response {
  return Response.json({ code, message }, { status });
}

function redirect(location: string, headers: Record<string, string> = {}) {
  return new Response(null, {
    status: 302,
    headers: { location, "cache-control": "no-store", ...headers },
  });
}

function loginError(code: OidcLoginError, returnTo: string | undefined) {
  const query = new URLSearchParams({ error: code });
  if (returnTo !== undefined && returnTo !== "/") query.set("return", returnTo);
  return redirect(`/login?${query.toString()}`);
}

/** Names and OAuth error codes only: messages from the provider may echo request data. */
function describeError(error: unknown): string {
  if (!(error instanceof Error)) return "unknown error";
  const fields = error as Error & { code?: unknown; error?: unknown };
  const code = typeof fields.code === "string" ? ` ${fields.code}` : "";
  const oauth = typeof fields.error === "string" ? ` (${fields.error})` : "";
  return `${error.name}${code}${oauth}: ${error.message}`;
}

const idTokenClaims = z.object({
  sub: z.string().min(1),
  email: z.string().min(1),
  name: z.unknown().optional(),
  email_verified: z.unknown().optional(),
});

interface Claims {
  readonly subject: string;
  readonly email: string;
  readonly name: string | undefined;
  readonly isEmailVerified: boolean;
}

/** Undefined without a `sub` or `email`; a malformed `name` or `email_verified` is ignored. */
function readClaims(claims: Record<string, unknown> | undefined) {
  const parsed = idTokenClaims.safeParse(claims);
  if (!parsed.success) return undefined;
  const { sub, email, name, email_verified: emailVerified } = parsed.data;
  const result: Claims = {
    subject: sub,
    email,
    name: typeof name === "string" && name.trim() !== "" ? name : undefined,
    isEmailVerified: emailVerified === true,
  };
  return result;
}

const startQuery = z.object({
  return: z
    .string()
    .refine(isSafeReturnPath, { error: "return must be a path on this site" })
    .default("/"),
  invitation: z
    .string()
    .max(MAX_PARAM_LENGTH, { error: "invalid invitation" })
    .optional(),
});

const callbackQuery = z.object({
  state: z.string().min(1).max(MAX_PARAM_LENGTH),
});

const START_ERROR_CODES = {
  return: "oidc/invalid-return",
  invitation: "oidc/invalid-invitation",
} as const;

/** The first problem of a start query, as an error response. */
function startQueryError(error: z.ZodError): Response {
  const [issue] = error.issues;
  const key = issue?.path[0] === "invitation" ? "invitation" : "return";
  return jsonError(
    400,
    START_ERROR_CODES[key],
    issue?.message ?? "invalid query",
  );
}

/** The parameters present in `query`; a repeated parameter counts by its first value, like `get`. */
function queryParams(query: URLSearchParams): Record<string, string> {
  const params: Record<string, string> = {};
  for (const [key, value] of query) params[key] ??= value;
  return params;
}

function createDiscovery(
  source: OidcSource,
  isInsecureAllowed: boolean,
): () => Promise<Configuration> {
  let configuration: Promise<Configuration> | undefined;
  return () => {
    configuration ??= discovery(
      source.issuer,
      source.clientId,
      source.clientSecret,
      source.clientSecret === undefined ? None() : undefined,
      isInsecureAllowed ? { execute: [allowInsecureRequests] } : undefined,
    ).catch((error: unknown) => {
      // Not cached, so the next sign-in tries again.
      configuration = undefined;
      throw error;
    });
    return configuration;
  };
}

/**
 * Registers an identity provider and the start and callback routes for
 * every configured source. Everything is registered through `ctx`.
 */
export function registerOidc(
  ctx: Context,
  config: OidcConfig,
  options: OidcOptions = {},
): void {
  const logger = ctx.logger("oidc");
  const pending = createPendingLogins(
    ctx.storage,
    PLUGIN_NAME,
    options.now ?? Date.now,
  );

  ctx.effect(() => {
    const timer = setInterval(() => {
      pending.sweep().catch((error: unknown) => {
        logger.warn("pending-login sweep failed: %s", describeError(error));
      });
    }, SWEEP_INTERVAL_MS);
    timer.unref();
    return () => clearInterval(timer);
  }, "oidc pending-login sweep");

  const redirectUri = (request: Request, source: OidcSource): string =>
    `${config.publicUrl ?? new URL(request.url).origin}${callbackPath(source)}`;

  async function isInvitedSignup(
    token: string | undefined,
    email: string,
  ): Promise<boolean> {
    if (token === undefined) return false;
    const invitation = await ctx.identity.findInvitation(token);
    if (invitation === undefined) return false;
    return (
      invitation.email === undefined ||
      invitation.email.toLowerCase() === email.toLowerCase()
    );
  }

  for (const source of config.sources) {
    const discover = createDiscovery(source, config.allowInsecureRequests);

    ctx.identity.registerProvider(providerId(source), {
      display: { label: source.label, href: startPath(source) },
      // Sign-in happens by redirect through the routes below.
      authenticate: async () => undefined,
    });

    ctx.http.route(
      "GET",
      startPath(source),
      async ({ request }) => {
        const parsed = startQuery.safeParse(
          queryParams(new URL(request.url).searchParams),
        );
        if (!parsed.success) return startQueryError(parsed.error);
        const { return: returnTo, invitation } = parsed.data;

        let configuration: Configuration;
        try {
          configuration = await discover();
        } catch (error) {
          logger.warn(
            "discovery failed for source %s: %s",
            source.id,
            describeError(error),
          );
          return loginError("oidc-failed", returnTo);
        }

        const codeVerifier = randomPKCECodeVerifier();
        const state = randomState();
        const nonce = randomNonce();
        const login: PendingLogin = {
          sourceId: source.id,
          codeVerifier,
          nonce,
          returnTo,
          invitation,
        };
        await pending.add(state, login);
        const url = buildAuthorizationUrl(configuration, {
          redirect_uri: redirectUri(request, source),
          scope: source.scopes.join(" "),
          code_challenge: await calculatePKCECodeChallenge(codeVerifier),
          code_challenge_method: "S256",
          state,
          nonce,
        });
        return redirect(url.href);
      },
      { public: true },
    );

    ctx.http.route(
      "GET",
      callbackPath(source),
      async ({ request }) => {
        const query = new URL(request.url).searchParams;
        const parsed = callbackQuery.safeParse(queryParams(query));
        const state = parsed.success ? parsed.data.state : undefined;
        const login =
          state === undefined ? undefined : await pending.take(state);
        if (state === undefined || login?.sourceId !== source.id) {
          logger.warn(
            "callback for source %s with an unknown or expired state",
            source.id,
          );
          return loginError("oidc-failed", undefined);
        }

        let claims: Claims | undefined;
        try {
          // The redirect URI sent to the token endpoint must be the one used
          // at the start, also behind a proxy that rewrites the request URL.
          const currentUrl = new URL(redirectUri(request, source));
          currentUrl.search = query.toString();
          const tokens = await authorizationCodeGrant(
            await discover(),
            currentUrl,
            {
              pkceCodeVerifier: login.codeVerifier,
              expectedState: state,
              expectedNonce: login.nonce,
              idTokenExpected: true,
            },
          );
          claims = readClaims(tokens.claims());
        } catch (error) {
          logger.warn(
            "sign-in through source %s failed: %s",
            source.id,
            describeError(error),
          );
          return loginError("oidc-failed", login.returnTo);
        }
        if (claims === undefined) {
          logger.warn(
            "source %s returned an ID token without sub or email",
            source.id,
          );
          return loginError("oidc-failed", login.returnTo);
        }

        const allowSignup =
          source.signup === "auto" ||
          (await isInvitedSignup(login.invitation, claims.email));
        const user = await ctx.identity.resolveExternal(
          providerId(source),
          {
            subject: claims.subject,
            email: claims.email,
            name: claims.name ?? claims.email,
            isEmailVerified: claims.isEmailVerified,
          },
          { allowSignup },
        );
        if (user === undefined) {
          const existing = await ctx.identity.findUserByEmail(claims.email);
          return loginError(
            existing !== undefined && !claims.isEmailVerified
              ? "oidc-email-unverified"
              : "oidc-signup-required",
            login.returnTo,
          );
        }

        const token = await ctx.identity.createSession(user.id);
        return redirect(login.returnTo, {
          "set-cookie": ctx.http.sessionCookie(request, token),
        });
      },
      { public: true },
    );
  }
}
