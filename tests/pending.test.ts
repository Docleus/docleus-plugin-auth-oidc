import { createStorageService } from "@docleus/core-storage";
import { Context, type StorageService } from "@docleus/sdk";
import { testStorageLocation } from "@docleus/testing";
import { sql } from "kysely";
import { afterEach, describe, expect, it } from "vitest";
import {
  createPendingLogins,
  type PendingLogin,
} from "../src/server/pending.ts";

const login: PendingLogin = {
  sourceId: "corp",
  codeVerifier: "v",
  nonce: "n",
  returnTo: "/",
  invitation: undefined,
};

const disposers: (() => Promise<void>)[] = [];
afterEach(async () => {
  await Promise.all(disposers.splice(0).map((dispose) => dispose()));
});

async function freshStorage(): Promise<StorageService> {
  const location = await testStorageLocation();
  let storage: StorageService | undefined;
  const fiber = await new Context().plugin((ctx: Context) => {
    storage = createStorageService(ctx, location);
    ctx.provide("storage", storage);
  });
  disposers.push(() => fiber.dispose());
  if (storage === undefined) throw new Error("expected storage");
  return storage;
}

async function fresh(now: () => number, ttlMs?: number, max?: number) {
  const storage = await freshStorage();
  return {
    storage,
    pending: createPendingLogins(storage, "test.oidc", now, ttlMs, max),
  };
}

describe("createPendingLogins", () => {
  it("hands out each login once", async () => {
    const { pending } = await fresh(() => 0);
    await pending.add("s1", { ...login, invitation: "inv" });
    expect(await pending.take("s1")).toEqual({ ...login, invitation: "inv" });
    expect(await pending.take("s1")).toBeUndefined();
    expect(await pending.take("unknown")).toBeUndefined();
  });

  it("expires logins after the TTL", async () => {
    let time = 0;
    const { pending } = await fresh(() => time, 1000);
    await pending.add("s1", login);
    await pending.add("s2", login);
    time = 999;
    expect(await pending.take("s1")).toEqual(login);
    time = 1000;
    expect(await pending.take("s2")).toBeUndefined();
    expect(await pending.count()).toBe(0);
  });

  it("sweeps expired logins", async () => {
    let time = 0;
    const { pending } = await fresh(() => time, 1000);
    await pending.add("old", login);
    time = 500;
    await pending.add("new", login);
    time = 1200;
    await pending.sweep();
    expect(await pending.count()).toBe(1);
    expect(await pending.take("new")).toEqual(login);
  });

  it("drops the oldest logins beyond the limit", async () => {
    let time = 0;
    const { pending } = await fresh(() => time, 1000, 2);
    await pending.add("a", login);
    time = 1;
    await pending.add("b", login);
    time = 2;
    await pending.add("c", login);
    expect(await pending.count()).toBe(2);
    expect(await pending.take("a")).toBeUndefined();
    expect(await pending.take("c")).toEqual(login);
  });

  it("shares logins between stores on one database", async () => {
    const storage = await freshStorage();
    const first = createPendingLogins(storage, "test.oidc", () => 0);
    const second = createPendingLogins(storage, "test.oidc", () => 0);
    await first.add("s1", login);
    expect(await second.take("s1")).toEqual(login);
    expect(await first.take("s1")).toBeUndefined();
  });

  it("stores only a hash of the state", async () => {
    const { storage, pending } = await fresh(() => 0);
    await pending.add("secret-state", login);
    const { rows } = await sql<{
      state_hash: string;
    }>`select state_hash from oidc_pending_logins`.execute(storage.db);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.state_hash).not.toContain("secret-state");
  });

  it("rejects a malformed stored login", async () => {
    const { storage, pending } = await fresh(() => 0);
    await pending.add("s1", login);
    await sql`update oidc_pending_logins set nonce = ''`.execute(storage.db);
    await expect(pending.take("s1")).rejects.toMatchObject({
      code: "oidc/invalid-pending-login",
    });
  });
});
