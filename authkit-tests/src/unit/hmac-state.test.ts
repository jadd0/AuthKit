/**
 * Unit tests for OIDC state payload HMAC signing and verification.
 * Source: src/server/providers/oidc/state/signState.ts + verifyState.ts
 *
 * R1 – tampered state with valid-looking but unsigned payload must be rejected.
 */
import { describe, it, expect } from "vitest";
import { createHmac, randomBytes } from "crypto";

interface OIDCStatePayload {
  nonce: string;
  codeChallenge: string;
  redirectTo: string;
  provider: string;
  createdAt: number;
}

const SECRET = "test-state-secret-minimum-32-characters!";

function signState(payload: OIDCStatePayload): string {
  const body = JSON.stringify(payload);
  const sig = createHmac("sha256", SECRET).update(body).digest("hex");
  return `${Buffer.from(body).toString("base64")}.${sig}`;
}

function verifyState(token: string): OIDCStatePayload {
  const [b64, sig] = token.split(".");
  if (!b64 || !sig) throw new Error("Invalid state token format");
  const body = Buffer.from(b64, "base64").toString("utf-8");
  const expected = createHmac("sha256", SECRET).update(body).digest("hex");
  if (sig !== expected)
    throw new Error("State token signature invalid – possible tampering");
  return JSON.parse(body) as OIDCStatePayload;
}

function makePayload(
  overrides: Partial<OIDCStatePayload> = {},
): OIDCStatePayload {
  return {
    nonce: randomBytes(16).toString("hex"),
    codeChallenge: randomBytes(32).toString("hex"),
    redirectTo: "/dashboard",
    provider: "google",
    createdAt: Date.now(),
    ...overrides,
  };
}

describe("signState", () => {
  it("produces a dot-separated base64.hex string", () => {
    const [, sig] = signState(makePayload()).split(".");
    expect(sig).toMatch(/^[a-f0-9]{64}$/);
  });

  it("encodes all payload fields in the base64 segment", () => {
    const p = makePayload();
    const [b64] = signState(p).split(".");
    expect(JSON.parse(Buffer.from(b64, "base64").toString())).toMatchObject(p);
  });

  it("is deterministic for the same payload", () => {
    const p = makePayload();
    expect(signState(p).split(".")[1]).toBe(signState(p).split(".")[1]);
  });

  it("different nonces produce different tokens", () => {
    expect(signState(makePayload())).not.toBe(signState(makePayload()));
  });
});

describe("verifyState – happy path", () => {
  it("round-trips without throwing", () => {
    expect(() => verifyState(signState(makePayload()))).not.toThrow();
  });

  it("returns the original payload fields intact", () => {
    const p = makePayload({ redirectTo: "/admin", provider: "github" });
    const r = verifyState(signState(p));
    expect(r.redirectTo).toBe("/admin");
    expect(r.provider).toBe("github");
    expect(r.nonce).toBe(p.nonce);
  });
});

describe("verifyState – tampering rejection", () => {
  it("throws on an unsigned (raw JSON base64) state value", () => {
    const raw = Buffer.from(JSON.stringify(makePayload())).toString("base64");
    expect(() => verifyState(raw)).toThrow();
  });

  it("throws when signature replaced with all-zeros", () => {
    const [b64] = signState(makePayload()).split(".");
    expect(() => verifyState(`${b64}.${"0".repeat(64)}`)).toThrow(
      "signature invalid",
    );
  });

  it("throws when signature replaced with random hex", () => {
    const [b64] = signState(makePayload()).split(".");
    expect(() =>
      verifyState(`${b64}.${randomBytes(32).toString("hex")}`),
    ).toThrow("signature invalid");
  });

  it("throws when redirectTo is mutated (attacker changes post-login destination)", () => {
    const token = signState(makePayload({ redirectTo: "/dashboard" }));
    const [b64, sig] = token.split(".");
    const body = JSON.parse(Buffer.from(b64, "base64").toString());
    body.redirectTo = "/admin";
    const mutated = Buffer.from(JSON.stringify(body)).toString("base64");
    expect(() => verifyState(`${mutated}.${sig}`)).toThrow("signature invalid");
  });

  it("throws when provider is mutated", () => {
    const token = signState(makePayload({ provider: "google" }));
    const [b64, sig] = token.split(".");
    const body = JSON.parse(Buffer.from(b64, "base64").toString());
    body.provider = "evil";
    const mutated = Buffer.from(JSON.stringify(body)).toString("base64");
    expect(() => verifyState(`${mutated}.${sig}`)).toThrow("signature invalid");
  });

  it("throws on empty string", () => {
    expect(() => verifyState("")).toThrow();
  });

  it("throws on token with no dot separator (valid-looking unsigned payload)", () => {
    expect(() => verifyState("nodotinhere")).toThrow(
      "Invalid state token format",
    );
  });
});
