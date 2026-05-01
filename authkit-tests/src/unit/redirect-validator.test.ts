import { describe, it, expect } from "vitest";

function validateRedirectUri(
  uri: string,
  allow: string[],
  env = "production",
): { valid: boolean; reason?: string } {
  if (!uri) return { valid: false, reason: "Redirect URI is required" };
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return { valid: false, reason: "Redirect URI is malformed" };
  }
  const local = ["localhost", "127.0.0.1", "::1"].includes(u.hostname);
  if (u.protocol === "http:" && !local && env === "production")
    return {
      valid: false,
      reason: "HTTP redirect URIs are not allowed in production",
    };
  for (const a of allow) {
    const au = new URL(a);
    if (
      u.protocol === au.protocol &&
      u.hostname === au.hostname &&
      u.port === au.port &&
      u.pathname === au.pathname
    )
      return { valid: true };
  }
  return {
    valid: false,
    reason: `Redirect URI ${uri} does not match any allowed redirect.`,
  };
}

const AL = [
  "https://myapp.com/api/auth/provider/google/callback",
  "https://myapp.com/api/auth/provider/github/callback",
];

describe("validateRedirectUri — exact match (valid)", () => {
  it("accepts a URI that exactly matches first allow-list entry", () => {
    expect(
      validateRedirectUri(
        "https://myapp.com/api/auth/provider/google/callback",
        AL,
      ).valid,
    ).toBe(true);
  });
  it("accepts a URI that exactly matches second allow-list entry", () => {
    expect(
      validateRedirectUri(
        "https://myapp.com/api/auth/provider/github/callback",
        AL,
      ).valid,
    ).toBe(true);
  });
  it("accepts http://localhost in production (localhost exemption)", () => {
    expect(
      validateRedirectUri(
        "http://localhost:3000/cb",
        ["http://localhost:3000/cb"],
        "production",
      ).valid,
    ).toBe(true);
  });
});

describe("validateRedirectUri — protocol mismatch (rejected)", () => {
  it("rejects http:// when allow-list contains https://", () => {
    expect(
      validateRedirectUri(
        "http://myapp.com/api/auth/provider/google/callback",
        AL,
      ).valid,
    ).toBe(false);
  });
  it("rejects http:// non-localhost in production", () => {
    const r = validateRedirectUri(
      "http://myapp.com/api/auth/provider/google/callback",
      ["http://myapp.com/api/auth/provider/google/callback"],
      "production",
    );
    expect(r.valid).toBe(false);
    expect(r.reason).toContain("HTTP redirect URIs are not allowed");
  });
  it("accepts http:// in development", () => {
    expect(
      validateRedirectUri(
        "http://myapp.com/cb",
        ["http://myapp.com/cb"],
        "development",
      ).valid,
    ).toBe(true);
  });
});

describe("validateRedirectUri — hostname mismatch (rejected)", () => {
  it("rejects different hostname (open-redirect)", () => {
    expect(
      validateRedirectUri(
        "https://evil.com/api/auth/provider/google/callback",
        AL,
      ).valid,
    ).toBe(false);
  });
  it("rejects subdomain not in allow-list", () => {
    expect(
      validateRedirectUri(
        "https://sub.myapp.com/api/auth/provider/google/callback",
        AL,
      ).valid,
    ).toBe(false);
  });
});

describe("validateRedirectUri — port mismatch (rejected)", () => {
  it("rejects unexpected port", () => {
    expect(
      validateRedirectUri(
        "https://myapp.com:8080/api/auth/provider/google/callback",
        AL,
      ).valid,
    ).toBe(false);
  });
});

describe("validateRedirectUri — path mismatch (rejected)", () => {
  it("rejects different path", () => {
    expect(
      validateRedirectUri(
        "https://myapp.com/api/auth/provider/google/callback/extra",
        AL,
      ).valid,
    ).toBe(false);
  });
  it("rejects trailing slash not in allow-list", () => {
    expect(
      validateRedirectUri(
        "https://myapp.com/api/auth/provider/google/callback/",
        AL,
      ).valid,
    ).toBe(false);
  });
});

describe("validateRedirectUri — edge inputs", () => {
  it("rejects empty string", () => {
    expect(validateRedirectUri("", AL).valid).toBe(false);
  });
  it("rejects malformed URI", () => {
    expect(validateRedirectUri("not-a-url", AL).valid).toBe(false);
  });
  it("returns a descriptive reason on every rejection", () => {
    expect(validateRedirectUri("https://evil.com/cb", AL).reason).toBeTruthy();
  });
});
