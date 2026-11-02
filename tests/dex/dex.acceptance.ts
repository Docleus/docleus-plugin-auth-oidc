import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  createInstance,
  listen,
  type Instance,
  type Listening,
} from "@docleus/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const run = promisify(execFile);

// Keep in step with config.yaml.
const DEX_IMAGE = "ghcr.io/dexidp/dex:v2.46.1";
const DEX_ISSUER = "http://127.0.0.1:5556/dex";
const INSTANCE_PORT = 4320;
const INSTANCE_URL = `http://127.0.0.1:${INSTANCE_PORT}`;
const CONTAINER = `docleus-dex-acceptance-${process.pid}`;
const PLUGIN_DIR = fileURLToPath(new URL("../..", import.meta.url));
const CONFIG = fileURLToPath(new URL("config.yaml", import.meta.url));

/** Cookies per origin, enough for a redirect chain through Dex and the instance. */
function createCookieJar() {
  const cookies = new Map<string, Map<string, string>>();
  return {
    store(url: string, response: Response) {
      const origin = new URL(url).origin;
      const jar = cookies.get(origin) ?? new Map<string, string>();
      for (const header of response.headers.getSetCookie()) {
        const [pair = ""] = header.split(";");
        const index = pair.indexOf("=");
        if (index > 0) jar.set(pair.slice(0, index), pair.slice(index + 1));
      }
      cookies.set(origin, jar);
    },
    header(url: string): string {
      const jar = cookies.get(new URL(url).origin) ?? new Map<string, string>();
      return [...jar].map(([name, value]) => `${name}=${value}`).join("; ");
    },
  };
}

type CookieJar = ReturnType<typeof createCookieJar>;

async function request(jar: CookieJar, url: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  const cookie = jar.header(url);
  if (cookie !== "") headers.set("cookie", cookie);
  const response = await fetch(url, { ...init, headers, redirect: "manual" });
  jar.store(url, response);
  return response;
}

/** Follows redirects until a page that does not redirect; resolves to it and its URL. */
async function follow(jar: CookieJar, url: string, init: RequestInit = {}) {
  let current = url;
  let response = await request(jar, current, init);
  for (let hops = 0; response.status >= 300 && response.status < 400; hops++) {
    if (hops > 20) throw new Error("too many redirects");
    const location = response.headers.get("location");
    if (location === null)
      throw new Error(`redirect without location from ${current}`);
    current = new URL(location, current).href;
    response = await request(jar, current);
  }
  return { response, url: current };
}

function loginFormAction(html: string, pageUrl: string): string {
  const form = /<form\b[^>]*>/i.exec(html)?.[0] ?? "";
  const match = /\baction="([^"]*)"/i.exec(form);
  if (match?.[1] === undefined)
    throw new Error("no login form on the Dex page");
  return new URL(match[1].replaceAll("&amp;", "&"), pageUrl).href;
}

async function waitForDex(): Promise<void> {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(
        `${DEX_ISSUER}/.well-known/openid-configuration`,
      );
      if (response.ok) return;
    } catch {
      // Not listening yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  const { stdout, stderr } = await run("docker", ["logs", CONTAINER]).catch(
    () => ({ stdout: "", stderr: "" }),
  );
  throw new Error(`Dex did not start:\n${stdout}${stderr}`);
}

/** Signs in through Dex's password form; resolves to the instance's callback response. */
async function signInThroughDex(jar: CookieJar, returnTo: string) {
  const login = await follow(
    jar,
    `${INSTANCE_URL}/api/auth/oidc/dex/start?return=${encodeURIComponent(returnTo)}`,
  );
  expect(login.url.startsWith(DEX_ISSUER)).toBe(true);
  expect(login.response.status).toBe(200);
  const action = loginFormAction(await login.response.text(), login.url);

  let response = await request(jar, action, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      login: "ada@example.com",
      password: "password",
    }),
  });
  let url = action;
  // Through Dex's approval redirect, stopping at the instance's callback.
  while (!url.startsWith(`${INSTANCE_URL}/api/auth/oidc/dex/callback`)) {
    const location = response.headers.get("location");
    if (location === null) {
      throw new Error(
        `Dex answered ${response.status} at ${url}: ${await response.text()}`,
      );
    }
    url = new URL(location, url).href;
    response = await request(jar, url);
  }
  return response;
}

describe("sign-in through Dex", () => {
  let instance: Instance;
  let server: Listening;

  beforeAll(async () => {
    await run("docker", [
      "run",
      "--detach",
      "--rm",
      "--name",
      CONTAINER,
      "--publish",
      "127.0.0.1:5556:5556",
      "--volume",
      `${CONFIG}:/etc/dex/config.yaml:ro`,
      DEX_IMAGE,
      "dex",
      "serve",
      "/etc/dex/config.yaml",
    ]);
    await waitForDex();
    instance = await createInstance({
      baseDir: PLUGIN_DIR,
      publicUrl: INSTANCE_URL,
      plugins: [
        {
          id: "oidc",
          plugin: PLUGIN_DIR,
          config: {
            sources: [
              {
                id: "dex",
                label: "Dex",
                issuer: DEX_ISSUER,
                clientId: "docleus",
                clientSecret: "docleus-dex-secret",
                signup: "auto",
              },
            ],
            publicUrl: INSTANCE_URL,
            allowInsecureRequests: true,
          },
        },
      ],
    });
    server = await listen(instance, { port: INSTANCE_PORT });
  });

  afterAll(async () => {
    await server?.close();
    await instance?.dispose();
    await run("docker", ["rm", "--force", CONTAINER]).catch(() => undefined);
  });

  it("offers Dex on the sign-in page", async () => {
    const response = await fetch(`${INSTANCE_URL}/api/auth/methods`);
    const methods = (await response.json()) as { providers: unknown };
    expect(methods.providers).toEqual([
      {
        id: "oidc.dex",
        display: { label: "Dex", href: "/api/auth/oidc/dex/start" },
      },
    ]);
  });

  it("signs in, starts a cookie session and signs in as the same user again", async () => {
    const jar = createCookieJar();
    const callback = await signInThroughDex(jar, "/docs");
    expect(callback.status).toBe(302);
    expect(callback.headers.get("location")).toBe("/docs");
    expect(callback.headers.get("set-cookie")).toMatch(
      /^docleus_session=[^;]+;.*HttpOnly/i,
    );

    const me = await request(jar, `${INSTANCE_URL}/api/me`);
    expect(me.status).toBe(200);
    const body = (await me.json()) as {
      user: { id: string; email: string; name: string };
    };
    expect(body.user).toMatchObject({ email: "ada@example.com", name: "ada" });

    const again = createCookieJar();
    await signInThroughDex(again, "/");
    const second = (await (
      await request(again, `${INSTANCE_URL}/api/me`)
    ).json()) as {
      user: { id: string };
    };
    expect(second.user.id).toBe(body.user.id);
  });

  it("does not answer /api/me without the session", async () => {
    expect((await fetch(`${INSTANCE_URL}/api/me`)).status).toBe(401);
  });
});
