import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { PENDING_LOGIN_TTL_MS } from "../src/server/index.ts";
import { startFakeProvider, type FakeProvider } from "./fake-provider.ts";
import { loadPlugin, ORIGIN, sessionToken, type Instance } from "./instance.ts";

const START = "/api/auth/oidc/test/start";
const CALLBACK = `${ORIGIN}/api/auth/oidc/test/callback`;

let provider: FakeProvider;
let instance: Instance | undefined;
let time = 1_000_000;
const now = () => time;

beforeEach(async () => {
  provider = await startFakeProvider();
  time = 1_000_000;
});

afterEach(async () => {
  await instance?.dispose();
  instance = undefined;
  await provider.close();
});

function source(overrides: Record<string, unknown> = {}) {
  return {
    id: "test",
    label: "Test IdP",
    issuer: provider.issuer,
    clientId: provider.clientId,
    clientSecret: provider.clientSecret,
    ...overrides,
  };
}

async function load(
  overrides: Record<string, unknown> = {},
  extra: Record<string, unknown> = {},
): Promise<Instance> {
  instance = await loadPlugin(
    { sources: [source(overrides)], allowInsecureRequests: true, ...extra },
    { now },
  );
  return instance;
}

/** Starts a sign-in and lets the fake provider redirect back; resolves to the callback URL. */
async function authorize(app: Instance, query = ""): Promise<string> {
  const start = await app.fetch(`${START}${query}`);
  expect(start.status).toBe(302);
  const location = start.headers.get("location");
  if (location === null) throw new Error("start did not redirect");
  const response = await fetch(location, { redirect: "manual" });
  const callback = response.headers.get("location");
  if (callback === null) throw new Error("provider did not redirect");
  return callback;
}

async function signIn(app: Instance, query = ""): Promise<Response> {
  return app.fetch(await authorize(app, query));
}

function loginError(response: Response): string | null {
  expect(response.status).toBe(302);
  expect(response.headers.get("set-cookie")).toBeNull();
  const location = new URL(response.headers.get("location") ?? "", ORIGIN);
  expect(location.pathname).toBe("/login");
  return location.searchParams.get("error");
}

describe("provider registration", () => {
  it("offers each source on the sign-in page", async () => {
    const app = await load();
    expect(app.root.identity.providers()).toEqual([
      { id: "oidc.test", display: { label: "Test IdP", href: START } },
    ]);
  });

  it("does not sign in with credentials, only by redirect", async () => {
    const app = await load({ signup: "auto" });
    expect(await app.root.identity.login("oidc.test", {})).toBeUndefined();
  });

  it("removes the provider and its routes when the plugin unloads", async () => {
    const app = await load();
    await app.unloadPlugin();
    expect(app.root.identity.providers()).toEqual([]);
    expect((await app.fetch(START)).status).toBe(404);
  });
});

describe("GET start", () => {
  it("redirects to the provider with PKCE, state and nonce", async () => {
    const app = await load();
    const response = await app.fetch(START);
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location") ?? "");
    expect(`${location.origin}${location.pathname}`).toBe(
      `${provider.issuer}/authorize`,
    );
    const query = location.searchParams;
    expect(query.get("response_type")).toBe("code");
    expect(query.get("client_id")).toBe(provider.clientId);
    expect(query.get("redirect_uri")).toBe(CALLBACK);
    expect(query.get("scope")).toBe("openid email profile");
    expect(query.get("code_challenge_method")).toBe("S256");
    expect(query.get("code_challenge")).toMatch(/^[\w-]{43}$/);
    expect(query.get("state")).toMatch(/^[\w-]{20,}$/);
    expect(query.get("nonce")).toMatch(/^[\w-]{20,}$/);

    const again = new URL(
      (await app.fetch(START)).headers.get("location") ?? "",
    );
    expect(again.searchParams.get("state")).not.toBe(query.get("state"));
    expect(again.searchParams.get("nonce")).not.toBe(query.get("nonce"));
    expect(again.searchParams.get("code_challenge")).not.toBe(
      query.get("code_challenge"),
    );
  });

  it("uses the configured scopes and public URL", async () => {
    const app = await load(
      { scopes: ["openid", "email"] },
      { publicUrl: "https://docs.example.com" },
    );
    const location = new URL(
      (await app.fetch(START)).headers.get("location") ?? "",
    );
    expect(location.searchParams.get("scope")).toBe("openid email");
    expect(location.searchParams.get("redirect_uri")).toBe(
      "https://docs.example.com/api/auth/oidc/test/callback",
    );
  });

  it.each([
    "//evil.example",
    "/\\evil.example",
    "https://evil.example/",
    "docs",
  ])("rejects the return path %j", async (returnTo) => {
    const app = await load();
    const response = await app.fetch(
      `${START}?return=${encodeURIComponent(returnTo)}`,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({
      code: "oidc/invalid-return",
    });
    expect(provider.discoveryRequests).toBe(0);
  });

  it("rejects an invitation token longer than 2048 characters", async () => {
    const app = await load();
    const response = await app.fetch(`${START}?invitation=${"a".repeat(2049)}`);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({
      code: "oidc/invalid-invitation",
    });
    expect(provider.discoveryRequests).toBe(0);
  });

  it("sends the user back to the sign-in page when discovery fails, and retries it", async () => {
    const app = await load();
    provider.isDiscoveryDown = true;
    expect(loginError(await app.fetch(`${START}?return=/docs`))).toBe(
      "oidc-failed",
    );
    expect(app.warnings.join("\n")).toContain(
      "discovery failed for source test",
    );

    provider.isDiscoveryDown = false;
    expect((await app.fetch(START)).status).toBe(302);
    expect((await app.fetch(START)).status).toBe(302);
    expect(provider.discoveryRequests).toBe(2);
  });
});

describe("GET callback", () => {
  it("creates the user when signup is automatic and starts a session", async () => {
    const app = await load({ signup: "auto" });
    provider.user = {
      sub: "ada",
      email: "Ada@Example.com",
      email_verified: true,
      name: "Ada Lovelace",
    };
    const response = await signIn(app, "?return=%2Fdocs%3Fpage%3D2");
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/docs?page=2");
    const cookie = response.headers.get("set-cookie");
    expect(cookie).toMatch(/HttpOnly/i);
    const token = sessionToken(cookie);
    if (token === undefined) throw new Error("expected a session cookie");

    const user = await app.root.identity.authenticate(token);
    expect(user).toMatchObject({
      email: "ada@example.com",
      name: "Ada Lovelace",
    });
    const me = await app.fetch("/api/test/me", {
      headers: { cookie: `docleus_session=${token}` },
    });
    expect(await me.json()).toEqual({ userId: user?.id });
  });

  it("returns to / and names the user by email when the provider sends no name", async () => {
    const app = await load({ signup: "auto" });
    provider.user = {
      sub: "bob",
      email: "bob@example.com",
      email_verified: true,
    };
    const response = await signIn(app);
    expect(response.headers.get("location")).toBe("/");
    const token = sessionToken(response.headers.get("set-cookie"));
    expect(await app.root.identity.authenticate(token ?? "")).toMatchObject({
      name: "bob@example.com",
    });
  });

  it("signs in the same user again through the identity link", async () => {
    const app = await load({ signup: "auto" });
    const first = sessionToken((await signIn(app)).headers.get("set-cookie"));
    provider.user = { ...provider.user, email: "renamed@example.com" };
    const second = sessionToken((await signIn(app)).headers.get("set-cookie"));
    const a = await app.root.identity.authenticate(first ?? "");
    const b = await app.root.identity.authenticate(second ?? "");
    expect(a?.id).toBeDefined();
    expect(b?.id).toBe(a?.id);
    expect(await app.root.identity.countUsers()).toBe(1);
  });

  it("rejects an unknown person when signup needs an invitation", async () => {
    const app = await load();
    expect(loginError(await signIn(app, "?return=/docs"))).toBe(
      "oidc-signup-required",
    );
    expect(await app.root.identity.countUsers()).toBe(0);
  });

  it("keeps the return path on the sign-in page redirect", async () => {
    const app = await load();
    const response = await signIn(app, "?return=/docs");
    const location = new URL(response.headers.get("location") ?? "", ORIGIN);
    expect(location.searchParams.get("return")).toBe("/docs");
  });

  it("creates the user when an invitation for their email allows it", async () => {
    const app = await load();
    const { token } = await app.root.identity.createInvitation({
      email: "ada@example.com",
      data: { kind: "test" },
    });
    const returnTo = `/invitations/${token}`;
    const response = await signIn(
      app,
      `?invitation=${token}&return=${encodeURIComponent(returnTo)}`,
    );
    expect(response.headers.get("location")).toBe(returnTo);
    expect(sessionToken(response.headers.get("set-cookie"))).toBeDefined();
    expect(
      await app.root.identity.findUserByEmail("ada@example.com"),
    ).toBeDefined();
    // Accepting it (and granting what it grants) is up to the invitation page.
    expect(await app.root.identity.findInvitation(token)).toBeDefined();
  });

  it("creates the user when an invitation without an email allows it", async () => {
    const app = await load();
    const { token } = await app.root.identity.createInvitation({ data: {} });
    const response = await signIn(app, `?invitation=${token}`);
    expect(sessionToken(response.headers.get("set-cookie"))).toBeDefined();
  });

  it("rejects an invitation for another email, or an unknown one", async () => {
    const app = await load();
    const { token } = await app.root.identity.createInvitation({
      email: "someone-else@example.com",
      data: {},
    });
    expect(loginError(await signIn(app, `?invitation=${token}`))).toBe(
      "oidc-signup-required",
    );
    expect(loginError(await signIn(app, "?invitation=unknown"))).toBe(
      "oidc-signup-required",
    );
    expect(await app.root.identity.countUsers()).toBe(0);
  });

  it("links a verified email to the existing user", async () => {
    const app = await load();
    const existing = await app.root.identity.createUser({
      email: "ada@example.com",
      name: "Ada",
    });
    const response = await signIn(app);
    const token = sessionToken(response.headers.get("set-cookie"));
    expect((await app.root.identity.authenticate(token ?? ""))?.id).toBe(
      existing.id,
    );
  });

  it("rejects an unverified email that belongs to an existing user", async () => {
    const app = await load({ signup: "auto" });
    await app.root.identity.createUser({
      email: "ada@example.com",
      name: "Ada",
    });
    provider.user = {
      sub: "mallory",
      email: "ada@example.com",
      email_verified: false,
    };
    expect(loginError(await signIn(app))).toBe("oidc-email-unverified");
    expect(await app.root.identity.countUsers()).toBe(1);
  });

  it("rejects an ID token without an email", async () => {
    const app = await load({ signup: "auto" });
    provider.user = { sub: "nobody" };
    expect(loginError(await signIn(app))).toBe("oidc-failed");
    expect(app.warnings.join("\n")).toContain("without sub or email");
  });

  it("ignores a name or email_verified claim of the wrong type", async () => {
    const app = await load({ signup: "auto" });
    provider.user = {
      sub: "odd",
      email: "odd@example.com",
      // The provider sends what it likes; these are not what the spec says.
      name: 42 as unknown as string,
      email_verified: "true" as unknown as boolean,
    };
    const response = await signIn(app);
    const token = sessionToken(response.headers.get("set-cookie"));
    expect(await app.root.identity.authenticate(token ?? "")).toMatchObject({
      name: "odd@example.com",
    });
    const [user] = await app.root.identity.listUsers();
    expect(user?.email).toBe("odd@example.com");
  });

  it("rejects an unknown state", async () => {
    const app = await load({ signup: "auto" });
    const callback = new URL(await authorize(app));
    callback.searchParams.set("state", "forged");
    expect(loginError(await app.fetch(callback.href))).toBe("oidc-failed");
    expect(loginError(await app.fetch(`${CALLBACK}?code=x`))).toBe(
      "oidc-failed",
    );
    expect(app.warnings.join("\n")).toContain("unknown or expired state");
  });

  it("accepts each state once", async () => {
    const app = await load({ signup: "auto" });
    const callback = await authorize(app);
    expect(
      (await app.fetch(callback)).headers.get("set-cookie"),
    ).not.toBeNull();
    expect(loginError(await app.fetch(callback))).toBe("oidc-failed");
  });

  it("rejects a state older than ten minutes", async () => {
    const app = await load({ signup: "auto" });
    const callback = await authorize(app);
    time += PENDING_LOGIN_TTL_MS + 1;
    expect(loginError(await app.fetch(callback))).toBe("oidc-failed");
  });

  it("finishes a sign-in on another process that shares the database", async () => {
    const config = {
      sources: [source({ signup: "auto" })],
      allowInsecureRequests: true,
    };
    const first = await loadPlugin(config, { now });
    try {
      instance = await loadPlugin(config, { now }, first.root.storage);
      const callback = await authorize(first);
      const response = await instance.fetch(callback);
      expect(response.status).toBe(302);
      expect(sessionToken(response.headers.get("set-cookie"))).toBeDefined();
      expect(loginError(await first.fetch(callback))).toBe("oidc-failed");
    } finally {
      await instance?.dispose();
      instance = undefined;
      await first.dispose();
    }
  });

  it("rejects a state started for another source", async () => {
    instance = await loadPlugin(
      {
        sources: [source(), source({ id: "other", label: "Other" })],
        allowInsecureRequests: true,
      },
      { now },
    );
    const callback = new URL(await authorize(instance));
    callback.pathname = "/api/auth/oidc/other/callback";
    expect(loginError(await instance.fetch(callback.href))).toBe("oidc-failed");
  });

  it("sends the PKCE verifier and the original redirect URI to the token endpoint", async () => {
    const app = await load({ signup: "auto" });
    await signIn(app);
    expect(provider.lastTokenRequest?.get("redirect_uri")).toBe(CALLBACK);
    expect(provider.lastTokenRequest?.get("code_verifier")).toMatch(
      /^[\w-]{43,}$/,
    );
  });

  it("logs a provider error without secrets and sends the user back", async () => {
    const app = await load({ signup: "auto" });
    const callback = await authorize(app, "?return=/docs");
    provider.tokenError = "invalid_grant";
    const response = await app.fetch(callback);
    expect(loginError(response)).toBe("oidc-failed");
    const warnings = app.warnings.join("\n");
    expect(warnings).toContain("sign-in through source test failed");
    expect(warnings).toContain("invalid_grant");
    expect(warnings).not.toContain(provider.clientSecret);
    expect(warnings).not.toContain("secret detail");
    expect(warnings).not.toContain(new URL(callback).searchParams.get("code"));
  });
});

describe("config", () => {
  it("fails to load with an invalid config", async () => {
    await expect(loadPlugin({ sources: [] })).rejects.toMatchObject({
      code: "oidc/invalid-config",
    });
  });
});
