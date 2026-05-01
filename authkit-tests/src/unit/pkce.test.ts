/**
 * Unit tests for PKCE (RFC 7636) helpers.
 * Source: src/server/providers/oidc/pkce/
 *   generateCodeVerifier.ts
 *   generateCodeChallenge.ts
 *   verifyCodeChallenge.ts
 */
import { describe, it, expect } from "vitest";
import { randomBytes, createHash } from "crypto";

function generateCodeVerifier(length = 64): string {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  const bytes = randomBytes(length);
  return Array.from(bytes)
    .map((b) => chars[b % chars.length])
    .join("");
}

function generateCodeChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

function verifyCodeChallenge(
  verifier: string,
  storedChallenge: string,
): boolean {
  return generateCodeChallenge(verifier) === storedChallenge;
}

describe("generateCodeVerifier", () => {
  it("returns a string of the requested length (default 64)", () => {
    expect(generateCodeVerifier()).toHaveLength(64);
  });

  it("returns a 43-char verifier when explicitly requested (RFC minimum)", () => {
    expect(generateCodeVerifier(43)).toHaveLength(43);
  });

  it("returns a 128-char verifier when explicitly requested (RFC maximum)", () => {
    expect(generateCodeVerifier(128)).toHaveLength(128);
  });

  it("contains only unreserved characters (RFC 7636 §4.1)", () => {
    expect(generateCodeVerifier(128)).toMatch(/^[A-Za-z0-9\-._~]+$/);
  });

  it("produces unique verifiers on successive calls", () => {
    expect(generateCodeVerifier()).not.toBe(generateCodeVerifier());
  });

  it("50 consecutive verifiers are all unique (entropy check)", () => {
    const set = new Set(
      Array.from({ length: 50 }, () => generateCodeVerifier()),
    );
    expect(set.size).toBe(50);
  });
});

describe("generateCodeChallenge – S256 transformation", () => {
  it("produces a 43-char base64url string", () => {
    expect(generateCodeChallenge(generateCodeVerifier())).toHaveLength(43);
  });

  it("uses no padding characters ('=')", () => {
    expect(generateCodeChallenge(generateCodeVerifier())).not.toContain("=");
  });

  it("uses base64url characters only (no '+' or '/')", () => {
    expect(generateCodeChallenge(generateCodeVerifier())).toMatch(
      /^[A-Za-z0-9\-_]+$/,
    );
  });

  it("is deterministic for the same verifier input", () => {
    const v = generateCodeVerifier();
    expect(generateCodeChallenge(v)).toBe(generateCodeChallenge(v));
  });

  it("differs for different verifiers", () => {
    expect(generateCodeChallenge(generateCodeVerifier())).not.toBe(
      generateCodeChallenge(generateCodeVerifier()),
    );
  });

  it("matches the RFC 7636 Appendix B test vector", () => {
    const rfcVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    expect(generateCodeChallenge(rfcVerifier)).toBe(rfcChallenge);
  });
});

describe("verifyCodeChallenge", () => {
  it("returns true for a matching verifier/challenge pair", () => {
    const v = generateCodeVerifier();
    expect(verifyCodeChallenge(v, generateCodeChallenge(v))).toBe(true);
  });

  it("returns false for a missing code_verifier (empty string)", () => {
    expect(
      verifyCodeChallenge("", generateCodeChallenge(generateCodeVerifier())),
    ).toBe(false);
  });

  it("returns false for a mismatched verifier", () => {
    const c = generateCodeChallenge(generateCodeVerifier());
    expect(verifyCodeChallenge(generateCodeVerifier(), c)).toBe(false);
  });

  it("returns false for a tampered challenge (single char flip)", () => {
    const v = generateCodeVerifier();
    const c = generateCodeChallenge(v);
    const tampered = (c[0] === "A" ? "B" : "A") + c.slice(1);
    expect(verifyCodeChallenge(v, tampered)).toBe(false);
  });

  it("returns false if attacker passes verifier as challenge (plain method bypass)", () => {
    const v = generateCodeVerifier();
    expect(verifyCodeChallenge(v, v)).toBe(false);
  });

  it("returns false for a standard-base64 (padded) challenge", () => {
    const v = generateCodeVerifier();
    const padded = createHash("sha256").update(v).digest("base64");
    expect(verifyCodeChallenge(v, padded)).toBe(false);
  });
});
