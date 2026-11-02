import { DocleusError, z } from "@docleus/sdk";

export type SignupPolicy = "auto" | "invite";

export interface OidcSource {
  /** Part of the provider id (`oidc.<id>`) and of the route paths. */
  readonly id: string;
  /** Shown on the sign-in button. */
  readonly label: string;
  readonly issuer: URL;
  readonly clientId: string;
  /** Omitted for public clients, which rely on PKCE alone. */
  readonly clientSecret: string | undefined;
  readonly scopes: readonly string[];
  /** `auto` creates accounts on first sign-in; `invite` requires an invitation. */
  readonly signup: SignupPolicy;
}

export interface OidcConfig {
  readonly sources: readonly OidcSource[];
  /** Origin used for redirect URIs, for example behind a proxy; the request origin when omitted. */
  readonly publicUrl: string | undefined;
  /** Allows `http:` issuers, for local providers in tests. */
  readonly allowInsecureRequests: boolean;
}

export const DEFAULT_SCOPES: readonly string[] = ["openid", "email", "profile"];

const SOURCE_ID = /^[a-z0-9-]+$/;
const NON_EMPTY = "must be a non-empty string";

const text = z
  .string({ error: NON_EMPTY })
  .refine((value) => value.trim() !== "", { error: NON_EMPTY });

const httpUrl = text.transform((value, context) => {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    context.addIssue({ code: "custom", message: "must be a URL" });
    return z.NEVER;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    context.addIssue({ code: "custom", message: "must be an http(s) URL" });
    return z.NEVER;
  }
  if (url.search !== "" || url.hash !== "") {
    context.addIssue({
      code: "custom",
      message: "must not have a query or fragment",
    });
    return z.NEVER;
  }
  return url;
});

const sourceSchema = z.strictObject(
  {
    id: text.regex(SOURCE_ID, { error: `must match ${String(SOURCE_ID)}` }),
    label: text,
    issuer: httpUrl,
    clientId: text,
    clientSecret: text.optional(),
    scopes: z
      .array(z.string().regex(/^\S+$/, { error: "must be a scope name" }), {
        error: "must be a list of scope names",
      })
      .refine((scopes) => scopes.includes("openid"), {
        error: 'must include "openid"',
      })
      .optional(),
    signup: z
      .enum(["auto", "invite"], { error: 'must be "auto" or "invite"' })
      .default("invite"),
  },
  { error: "must be an object" },
);

const configSchema = z
  .strictObject(
    {
      sources: z
        .array(sourceSchema, { error: "must be a non-empty list" })
        .min(1, { error: "must be a non-empty list" }),
      publicUrl: httpUrl
        .refine((url) => url.pathname === "/", { error: "must be an origin" })
        .optional(),
      allowInsecureRequests: z
        .boolean({ error: "must be a boolean" })
        .default(false),
    },
    { error: "expected an object" },
  )
  .superRefine((config, context) => {
    const ids = new Set<string>();
    for (const [index, source] of config.sources.entries()) {
      if (source.issuer.protocol === "http:" && !config.allowInsecureRequests) {
        context.addIssue({
          code: "custom",
          path: ["sources", index, "issuer"],
          message: "must use https unless allowInsecureRequests is set",
        });
      }
      if (ids.has(source.id)) {
        context.addIssue({
          code: "custom",
          path: [],
          message: `duplicate source id ${JSON.stringify(source.id)}`,
        });
      }
      ids.add(source.id);
    }
  });

function formatPath(path: readonly PropertyKey[]): string {
  return path
    .map((key, index) =>
      typeof key === "number"
        ? `[${key}]`
        : `${index === 0 ? "" : "."}${String(key)}`,
    )
    .join("");
}

// Messages name the key and the rule, never the value, so a client secret is
// never echoed.
function describeIssue(issue: z.core.$ZodIssue): string {
  const path = formatPath(issue.path);
  if (issue.code === "unrecognized_keys") {
    return `unknown key ${JSON.stringify(issue.keys[0])} in ${path || "config"}`;
  }
  return path === "" ? issue.message : `${path} ${issue.message}`;
}

/** Validates the plugin config; throws `oidc/invalid-config` with the first problem found. */
export function parseOidcConfig(value: unknown): OidcConfig {
  const parsed = configSchema.safeParse(value);
  if (!parsed.success) {
    const [issue] = parsed.error.issues;
    throw new DocleusError(
      "oidc/invalid-config",
      `invalid config: ${issue ? describeIssue(issue) : "unknown problem"}`,
    );
  }
  const config = parsed.data;
  return {
    sources: config.sources.map((source): OidcSource => ({
      id: source.id,
      label: source.label,
      issuer: source.issuer,
      clientId: source.clientId,
      clientSecret: source.clientSecret,
      scopes:
        source.scopes === undefined
          ? DEFAULT_SCOPES
          : [...new Set(source.scopes)],
      signup: source.signup,
    })),
    publicUrl: config.publicUrl?.origin,
    allowInsecureRequests: config.allowInsecureRequests,
  };
}
