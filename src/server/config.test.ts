import { describe, expect, it } from "vitest";
import { DEFAULT_SCOPES, parseOidcConfig } from "./config.ts";

const source = {
  id: "corp",
  label: "Corp SSO",
  issuer: "https://idp.example.com/realms/corp",
  clientId: "docleus",
};

describe("parseOidcConfig", () => {
  it("applies the defaults", () => {
    const config = parseOidcConfig({ sources: [source] });
    expect(config).toEqual({
      sources: [
        {
          ...source,
          issuer: new URL(source.issuer),
          clientSecret: undefined,
          scopes: DEFAULT_SCOPES,
          signup: "invite",
        },
      ],
      publicUrl: undefined,
      allowInsecureRequests: false,
    });
    expect(DEFAULT_SCOPES).toEqual(["openid", "email", "profile"]);
  });

  it("keeps the given options", () => {
    const config = parseOidcConfig({
      sources: [
        {
          ...source,
          issuer: "http://localhost:5556/dex",
          clientSecret: "s3cret",
          scopes: ["openid", "email", "groups", "email"],
          signup: "auto",
        },
      ],
      publicUrl: "https://docs.example.com/",
      allowInsecureRequests: true,
    });
    expect(config.sources[0]).toMatchObject({
      clientSecret: "s3cret",
      scopes: ["openid", "email", "groups"],
      signup: "auto",
    });
    expect(config.publicUrl).toBe("https://docs.example.com");
    expect(config.allowInsecureRequests).toBe(true);
  });

  it.each([
    ["no object", undefined],
    ["no sources", {}],
    ["empty sources", { sources: [] }],
    ["unknown key", { sources: [source], extra: 1 }],
    ["unknown source key", { sources: [{ ...source, secret: "x" }] }],
    ["bad id", { sources: [{ ...source, id: "Corp_SSO" }] }],
    ["duplicate id", { sources: [source, source] }],
    ["missing label", { sources: [{ ...source, label: "" }] }],
    ["missing client id", { sources: [{ ...source, clientId: undefined }] }],
    ["empty secret", { sources: [{ ...source, clientSecret: "" }] }],
    ["bad issuer", { sources: [{ ...source, issuer: "not a url" }] }],
    [
      "ftp issuer",
      { sources: [{ ...source, issuer: "ftp://idp.example.com" }] },
    ],
    [
      "issuer query",
      { sources: [{ ...source, issuer: `${source.issuer}?a=1` }] },
    ],
    [
      "http issuer",
      { sources: [{ ...source, issuer: "http://idp.example.com" }] },
    ],
    ["scopes without openid", { sources: [{ ...source, scopes: ["email"] }] }],
    ["bad scope", { sources: [{ ...source, scopes: ["openid", "a b"] }] }],
    ["bad signup", { sources: [{ ...source, signup: "open" }] }],
    ["bad insecure flag", { sources: [source], allowInsecureRequests: "yes" }],
    [
      "public URL with path",
      { sources: [source], publicUrl: "https://x.example/docs" },
    ],
  ])("rejects %s", (_name, value) => {
    expect(() => parseOidcConfig(value)).toThrow(
      expect.objectContaining({ code: "oidc/invalid-config" }),
    );
  });

  it("does not echo the client secret in errors", () => {
    expect(() =>
      parseOidcConfig({
        sources: [{ ...source, clientSecret: "s3cret", signup: "open" }],
      }),
    ).toThrow(
      expect.not.objectContaining({
        message: expect.stringContaining("s3cret"),
      }),
    );
  });
});
