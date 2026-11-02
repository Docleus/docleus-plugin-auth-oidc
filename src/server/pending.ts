import { createHash } from "node:crypto";
import {
  DocleusError,
  z,
  type Migration,
  type StorageService,
} from "@docleus/sdk";
import type { Kysely } from "kysely";

/** A sign-in that was sent to the provider and has not come back yet. */
export interface PendingLogin {
  readonly sourceId: string;
  readonly codeVerifier: string;
  readonly nonce: string;
  readonly returnTo: string;
  readonly invitation: string | undefined;
}

/**
 * Pending sign-ins in `storage`, so the callback may reach another web
 * process than the one that started the sign-in.
 */
export interface PendingLogins {
  add(state: string, login: PendingLogin): Promise<void>;
  /** Removes and returns the login for `state` while it has not expired. */
  take(state: string): Promise<PendingLogin | undefined>;
  /** Deletes expired logins. */
  sweep(): Promise<void>;
  count(): Promise<number>;
}

export const PENDING_LOGIN_TTL_MS = 10 * 60 * 1000;
/** Bounds the table when someone starts sign-ins without finishing them. */
export const MAX_PENDING_LOGINS = 10_000;

interface PendingLoginsTable {
  state_hash: string;
  source_id: string;
  code_verifier: string;
  nonce: string;
  return_to: string;
  invitation: string | null;
  created_at: number;
  expires_at: number;
}

interface PendingSchema {
  oidc_pending_logins: PendingLoginsTable;
}

type Db = Kysely<PendingSchema>;

export const pendingMigrations: readonly Migration[] = [
  {
    id: "0001-pending-logins",
    async up(db: Kysely<unknown>) {
      const typed = db as unknown as Db;
      await typed.schema
        .createTable("oidc_pending_logins")
        .addColumn("state_hash", "text", (c) => c.primaryKey())
        .addColumn("source_id", "text", (c) => c.notNull())
        .addColumn("code_verifier", "text", (c) => c.notNull())
        .addColumn("nonce", "text", (c) => c.notNull())
        .addColumn("return_to", "text", (c) => c.notNull())
        .addColumn("invitation", "text")
        .addColumn("created_at", "integer", (c) => c.notNull())
        .addColumn("expires_at", "integer", (c) => c.notNull())
        .execute();
      await typed.schema
        .createIndex("oidc_pending_logins_expires_at")
        .on("oidc_pending_logins")
        .column("expires_at")
        .execute();
      await typed.schema
        .createIndex("oidc_pending_logins_created_at")
        .on("oidc_pending_logins")
        .columns(["created_at", "state_hash"])
        .execute();
    },
  },
];

const storedLogin = z.object({
  source_id: z.string(),
  code_verifier: z.string().min(1),
  nonce: z.string().min(1),
  return_to: z.string(),
  invitation: z.string().nullable(),
  expires_at: z.number(),
});

// The state travels through the browser and the provider; only its hash is
// kept, like session tokens.
function hashState(state: string): string {
  return createHash("sha256").update(state).digest("base64url");
}

export function createPendingLogins(
  storage: StorageService,
  owner: string,
  now: () => number,
  ttlMs = PENDING_LOGIN_TTL_MS,
  max = MAX_PENDING_LOGINS,
): PendingLogins {
  const db = storage.db as unknown as Db;
  const ready = storage.migrate(owner, pendingMigrations);

  return {
    async add(state, login) {
      const createdAt = now();
      await ready;
      await storage.transaction(async (raw) => {
        const trx = raw as unknown as Db;
        await trx
          .insertInto("oidc_pending_logins")
          .values({
            state_hash: hashState(state),
            source_id: login.sourceId,
            code_verifier: login.codeVerifier,
            nonce: login.nonce,
            return_to: login.returnTo,
            invitation: login.invitation ?? null,
            created_at: createdAt,
            expires_at: createdAt + ttlMs,
          })
          .execute();
        const { count } = await trx
          .selectFrom("oidc_pending_logins")
          .select((eb) => eb.fn.countAll<number>().as("count"))
          .executeTakeFirstOrThrow();
        const excess = Number(count) - max;
        if (excess <= 0) return;
        const oldest = await trx
          .selectFrom("oidc_pending_logins")
          .select("state_hash")
          .orderBy("created_at")
          .orderBy("state_hash")
          .limit(excess)
          .execute();
        await trx
          .deleteFrom("oidc_pending_logins")
          .where(
            "state_hash",
            "in",
            oldest.map((row) => row.state_hash),
          )
          .execute();
      });
    },
    async take(state) {
      await ready;
      // One statement, so two processes handed the same callback cannot
      // both get the login.
      const row = await db
        .deleteFrom("oidc_pending_logins")
        .where("state_hash", "=", hashState(state))
        .returningAll()
        .executeTakeFirst();
      if (row === undefined) return undefined;
      const parsed = storedLogin.safeParse(row);
      if (!parsed.success) {
        throw new DocleusError(
          "oidc/invalid-pending-login",
          "a stored pending sign-in is malformed",
          { cause: parsed.error },
        );
      }
      const stored = parsed.data;
      if (stored.expires_at <= now()) return undefined;
      return {
        sourceId: stored.source_id,
        codeVerifier: stored.code_verifier,
        nonce: stored.nonce,
        returnTo: stored.return_to,
        invitation: stored.invitation ?? undefined,
      };
    },
    async sweep() {
      await ready;
      await db
        .deleteFrom("oidc_pending_logins")
        .where("expires_at", "<=", now())
        .execute();
    },
    async count() {
      await ready;
      const { count } = await db
        .selectFrom("oidc_pending_logins")
        .select((eb) => eb.fn.countAll<number>().as("count"))
        .executeTakeFirstOrThrow();
      return Number(count);
    },
  };
}
