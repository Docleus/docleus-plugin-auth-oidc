import { createHash, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";

/** The person the fake provider signs in on its next authorization request. */
export interface FakeUser {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
}

interface IssuedCode {
  readonly user: FakeUser;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly codeChallenge: string;
  readonly nonce: string | undefined;
}

export interface FakeProvider {
  readonly issuer: string;
  readonly clientId: string;
  readonly clientSecret: string;
  /** Who signs in next; set per test. */
  user: FakeUser;
  /** Overrides the token endpoint's answer, for error tests. */
  tokenError: string | undefined;
  /** Makes discovery answer 503 while set. */
  isDiscoveryDown: boolean;
  /** Number of discovery requests served. */
  discoveryRequests: number;
  /** The query of the last authorization request. */
  lastAuthorization: URLSearchParams | undefined;
  /** The form of the last token request. */
  lastTokenRequest: URLSearchParams | undefined;
  close(): Promise<void>;
}

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

const s256 = (verifier: string): string =>
  createHash("sha256").update(verifier).digest("base64url");

/**
 * An OpenID Connect provider on a random local port: discovery, JWKS, an
 * authorization endpoint that signs in `user` without a login form, and a
 * token endpoint that checks the code, redirect URI, client secret and
 * PKCE verifier and returns an RS256 ID token.
 */
export async function startFakeProvider(): Promise<FakeProvider> {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk: JWK = { ...(await exportJWK(publicKey)), kid: "k1", use: "sig" };
  const codes = new Map<string, IssuedCode>();
  let issuer = "";

  const provider: FakeProvider = {
    get issuer() {
      return issuer;
    },
    clientId: "docleus",
    clientSecret: "fake-secret",
    user: { sub: "u1", email: "ada@example.com", email_verified: true },
    tokenError: undefined,
    isDiscoveryDown: false,
    discoveryRequests: 0,
    lastAuthorization: undefined,
    lastTokenRequest: undefined,
    close: () =>
      new Promise((resolve, reject) => {
        server.closeAllConnections();
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };

  const server: Server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", issuer);
    const json = (status: number, body: unknown) => {
      response.writeHead(status, { "content-type": "application/json" });
      response.end(JSON.stringify(body));
    };

    if (url.pathname === "/.well-known/openid-configuration") {
      provider.discoveryRequests += 1;
      if (provider.isDiscoveryDown) return json(503, { error: "down" });
      return json(200, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["client_secret_post"],
      });
    }
    if (url.pathname === "/jwks") return json(200, { keys: [jwk] });
    if (url.pathname === "/authorize") {
      const query = url.searchParams;
      provider.lastAuthorization = query;
      const redirectUri = query.get("redirect_uri") ?? "";
      const code = randomBytes(16).toString("base64url");
      codes.set(code, {
        user: { ...provider.user },
        clientId: query.get("client_id") ?? "",
        redirectUri,
        codeChallenge: query.get("code_challenge") ?? "",
        nonce: query.get("nonce") ?? undefined,
      });
      const location = new URL(redirectUri);
      location.searchParams.set("code", code);
      const state = query.get("state");
      if (state !== null) location.searchParams.set("state", state);
      response.writeHead(302, { location: location.href });
      return response.end();
    }
    if (url.pathname === "/token" && request.method === "POST") {
      void readBody(request)
        .then(async (body) => {
          const form = new URLSearchParams(body);
          provider.lastTokenRequest = form;
          if (provider.tokenError !== undefined) {
            return json(400, {
              error: provider.tokenError,
              error_description: "secret detail from the provider",
            });
          }
          const issued = codes.get(form.get("code") ?? "");
          codes.delete(form.get("code") ?? "");
          if (
            issued === undefined ||
            form.get("grant_type") !== "authorization_code" ||
            form.get("client_id") !== provider.clientId ||
            form.get("client_secret") !== provider.clientSecret ||
            form.get("redirect_uri") !== issued.redirectUri ||
            s256(form.get("code_verifier") ?? "") !== issued.codeChallenge
          ) {
            return json(400, { error: "invalid_grant" });
          }
          const idToken = await new SignJWT({
            ...issued.user,
            ...(issued.nonce !== undefined && { nonce: issued.nonce }),
          })
            .setProtectedHeader({ alg: "RS256", kid: "k1" })
            .setIssuer(issuer)
            .setAudience(issued.clientId)
            .setSubject(issued.user.sub)
            .setIssuedAt()
            .setExpirationTime("5m")
            .sign(privateKey);
          return json(200, {
            access_token: randomBytes(16).toString("base64url"),
            token_type: "Bearer",
            expires_in: 300,
            id_token: idToken,
          });
        })
        .catch(() => json(500, { error: "server_error" }));
      return;
    }
    return json(404, { error: "not_found" });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return provider;
}
