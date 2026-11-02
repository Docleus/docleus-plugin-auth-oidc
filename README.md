<p align="center">
  <a href="https://docleus.io"><img src="./.github/assets/docleus.svg" width="88" alt="Docleus logo" /></a>
</p>

<h1 align="center">OpenID Connect</h1>

<p align="center">
  <strong>One sign-in. Your identity provider.</strong><br />
  OpenID Connect sign-in with PKCE, invitations, and multiple providers.
</p>

<p align="center">
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-111111?style=flat-square" /></a>
  <img alt="Public preview in preparation" src="https://img.shields.io/badge/preview-0.0.1-cfcfcf?style=flat-square" />
  <img alt="TypeScript" src="https://img.shields.io/badge/TypeScript-strict-3178c6?style=flat-square" />
  <a href="https://docleus.io"><img alt="Online documentation" src="https://img.shields.io/badge/docs-docleus.io-111111?style=flat-square" /></a>
</p>

<p align="center">
  <a href="https://docleus.io">Documentation</a> &middot;
  <a href="#config">Configuration</a> &middot;
  <a href="https://github.com/Docleus/docleus">Run Docleus</a> &middot;
  <a href="https://github.com/Docleus/.github/blob/main/CONTRIBUTING.md">Contribute</a>
</p>

---

Sign-in through OpenID Connect providers (Keycloak, Authentik, Dex, Google, Entra ID, ...). Each configured source becomes an identity provider `oidc.<id>` with a button on the sign-in page. Sign-in is the authorization code flow with PKCE (S256), `state` and `nonce`, built on [`openid-client`](https://github.com/panva/openid-client).

## Config

Add this row to the `plugins` list in the deployment config. Paths resolve
relative to that file. In the default distribution, patch its existing
`oidc` row instead: omit `plugin` and add `disabled: false`.

```yaml
plugins:
  - id: oidc
    plugin: ../docleus-plugin-auth-oidc
    config:
      sources:
        - id: corp # /^[a-z0-9-]+$/
          label: Corp SSO # text of the sign-in button
          issuer: https://idp.example.com/realms/corp
          clientId: docleus
          clientSecret: ... # omit for a public client
          scopes: [openid, email, profile] # the default; must include openid
          signup: invite # or auto; the default is invite
      publicUrl: https://docs.example.com # optional; the request origin by default
      allowInsecureRequests: false # true allows http issuers, for local test providers only
```

An invalid config fails the plugin with `oidc/invalid-config`. Register the redirect URI `<publicUrl>/api/auth/oidc/<id>/callback` with the provider. Set `publicUrl` when the instance runs behind a proxy that changes the origin.

## Routes

- `GET /api/auth/oidc/<id>/start?return=<path>&invitation=<token>`: discovers the provider (once, cached; retried after a failure) and redirects to it. `return` must be a path on this site (`/...`, not `//...` or `/\...`); anything else answers 400 `oidc/invalid-return`.
- `GET /api/auth/oidc/<id>/callback`: exchanges the code, reads `sub`, `email` (required), `email_verified` and `name` from the ID token, and resolves the user with `ctx.identity.resolveExternal`. On success it sets the session cookie and redirects to `return` (default `/`).

A person without an account gets one when the source has `signup: auto`, or when the sign-in started with an invitation that is valid and either has no email or the same email. The invitation is not consumed here; the invitation page accepts it after sign-in. A verified email is linked to the existing user with that email; an unverified one is not.

Failures redirect to `/login?error=<code>` (with `return` when it is not `/`):

| Code                    | Meaning                                                                                                                                                            |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `oidc-signup-required`  | No account matches and signup is not allowed                                                                                                                       |
| `oidc-email-unverified` | An account has this email, but the provider did not verify it                                                                                                      |
| `oidc-failed`           | Discovery, the token exchange or the ID token failed, or the state is unknown, used or older than 10 minutes. Logged as a warning without tokens, codes or secrets |

Pending sign-ins are kept in the database (`ctx.storage`) for 10 minutes, so the callback may reach another web process than the one that started the sign-in. Only a hash of the state is stored.

## Tests

- `pnpm test`: unit tests, and integration tests (`tests/oidc.test.ts`) against the real core identity, authz, storage and http services with an in-process fake provider (`tests/fake-provider.ts`, ID tokens signed with `jose`).
- `pnpm test:dex`: acceptance test against [Dex](https://dexidp.io) `v2.46.1` in Docker (`tests/dex/config.yaml`: a static client and the password user `ada@example.com` / `password`). It builds the plugin, starts Dex on `127.0.0.1:5556`, boots an instance with `@docleus/server` on `127.0.0.1:4320`, signs in through Dex's login form without a browser, and checks the session on `/api/me`. Both ports must be free. It needs a running Docker daemon (for example `colima start`) and is not part of `pnpm check`.

## Development

Use Node.js 24 and pnpm 11.21.0. Keep this repository next to `docleus-core`
with its original directory name; the `link:` development dependencies need
that layout. Install core before this repository:

```sh
pnpm --dir ../docleus-core install --frozen-lockfile
pnpm install --frozen-lockfile
pnpm check
pnpm build
```

`pnpm check` runs typecheck, lint, formatting, dependency boundaries, licenses,
and unit/in-process integration tests. Browser and external-service tests,
where provided, are separate and need the sibling repositories listed in
their setup files. The SDK is a host-provided peer dependency; packages remain
private and are not installed from npm. All extension points are experimental
before 1.0.

## Community

[Contributing](https://github.com/Docleus/.github/blob/main/CONTRIBUTING.md) &middot;
[Code of conduct](https://github.com/Docleus/.github/blob/main/CODE_OF_CONDUCT.md) &middot;
[Security](https://github.com/Docleus/.github/blob/main/SECURITY.md) &middot;
[Support](https://github.com/Docleus/.github/blob/main/SUPPORT.md)

## License

[MIT](LICENSE)
