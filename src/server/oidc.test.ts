import { describe, expect, it } from "vitest";
import { isSafeReturnPath } from "./oidc.ts";

describe("isSafeReturnPath", () => {
  it.each(["/", "/docs", "/docs?page=2#top", "/invitations/abc", "/a//b"])(
    "accepts %j",
    (path) => {
      expect(isSafeReturnPath(path)).toBe(true);
    },
  );

  it.each([
    "",
    "docs",
    "//evil.example",
    "/\\evil.example",
    "https://evil.example/",
    "javascript:alert(1)",
    "/\tevil",
    "/\n/evil.example",
    `/${"a".repeat(3000)}`,
  ])("rejects %j", (path) => {
    expect(isSafeReturnPath(path)).toBe(false);
  });
});
