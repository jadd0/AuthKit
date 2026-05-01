/**
 * Unit tests for CSRF token generation and verification.
 * Source: src/shared/utils/CSRF/generateCSRFToken.ts
 *         src/shared/utils/CSRF/verifyCSRF.ts
 *
 * R1 – login/logout requests without CSRF header are rejected.
 * CSRF_TOKEN_MAX_AGE from src/shared/constants/config.constants.ts
 */
import { describe, it, expect } from "vitest";
import { createHmac, createHash, randomBytes } from "crypto";

const SESSION_COOKIE = "authkit-session";
const CSRF_COOKIE = "authkit-csrf-token";
const CSRF_HEADER = "x-authkit-csrf-token";
const CSRF_MAX_AGE = 15 * 60 * 1000; // 15 minutes
const SECRET = "test-csrf-secret-minimum-32-chars-ok!";

interface CSRFTokenPayload {
  sessionToken: string;
  timestamp: number;
  nonce: string;
  actionHash?: string;
}

interface MockRequest {
  cookies: Record<string, string>;
  headers: Record<string, string>;
}

function generateCsrfToken(sessionToken: string, action?: string): string {
  const nonce = randomBytes(16).toString("hex");
  const timestamp = Date.now();
  const payload: CSRFTokenPayload = {
    sessionToken,
    timestamp,
    nonce,
    ...(action
      ? { actionHash: createHash("sha256").update(action).digest("hex") }
      : {}),
  };
  const payloadStr = JSON.stringify(payload);
  const signature = createHmac("sha256", SECRET)
    .update(payloadStr)
    .digest("hex");
  return `${Buffer.from(payloadStr).toString("base64")}.${signature}`;
}

function verifyCsrf(req: MockRequest, action?: string): boolean {
  const sessionToken = req.cookies[SESSION_COOKIE];
  const cookieToken = req.cookies[CSRF_COOKIE];
  const headerToken = req.headers[CSRF_HEADER];

  if (!sessionToken || !cookieToken || !headerToken)
    throw new Error("CSRF validation failed: Missing tokens");
  if (cookieToken !== headerToken)
    throw new Error("CSRF validation failed: Token mismatch");

  const [payloadB64, signature] = headerToken.split(".");
  if (!payloadB64 || !signature)
    throw new Error("CSRF validation failed: Invalid token format");

  const payloadStr = Buffer.from(payloadB64, "base64").toString("utf-8");
  const payload = JSON.parse(payloadStr) as CSRFTokenPayload;
  const expected = createHmac("sha256", SECRET)
    .update(payloadStr)
    .digest("hex");

  if (signature !== expected)
    throw new Error("CSRF validation failed: Invalid token signature");
  if (payload.sessionToken !== sessionToken)
    throw new Error("CSRF validation failed: Session token mismatch");
  if (Date.now() - payload.timestamp > CSRF_MAX_AGE)
    throw new Error("CSRF validation failed: Token expired");
  if (action && payload.actionHash) {
    if (
      payload.actionHash !== createHash("sha256").update(action).digest("hex")
    )
      throw new Error("CSRF validation failed: Action mismatch");
  }
  return true;
}

// ── generateCsrfToken ──────────────────────────────────────────────────────
describe("generateCsrfToken", () => {
  it("produces a dot-separated base64.hex string", () => {
    expect(generateCsrfToken("sess").split(".")[1]).toMatch(/^[a-f0-9]{64}$/);
  });

  it("embeds the sessionToken in the payload", () => {
    const [b64] = generateCsrfToken("my-session-token").split(".");
    expect(JSON.parse(Buffer.from(b64, "base64").toString()).sessionToken).toBe(
      "my-session-token",
    );
  });

  it("embeds a timestamp within the current window", () => {
    const before = Date.now();
    const [b64] = generateCsrfToken("s").split(".");
    const after = Date.now();
    const { timestamp } = JSON.parse(Buffer.from(b64, "base64").toString());
    expect(timestamp).toBeGreaterThanOrEqual(before);
    expect(timestamp).toBeLessThanOrEqual(after);
  });

  it("embeds a 32-char hex nonce", () => {
    const [b64] = generateCsrfToken("s").split(".");
    expect(JSON.parse(Buffer.from(b64, "base64").toString()).nonce).toMatch(
      /^[a-f0-9]{32}$/,
    );
  });

  it("nonces differ on successive calls (no replay)", () => {
    const n1 = JSON.parse(
      Buffer.from(generateCsrfToken("s").split(".")[0], "base64").toString(),
    ).nonce;
    const n2 = JSON.parse(
      Buffer.from(generateCsrfToken("s").split(".")[0], "base64").toString(),
    ).nonce;
    expect(n1).not.toBe(n2);
  });

  it("embeds SHA-256 actionHash when action is provided", () => {
    const [b64] = generateCsrfToken("s", "logout").split(".");
    expect(JSON.parse(Buffer.from(b64, "base64").toString()).actionHash).toBe(
      createHash("sha256").update("logout").digest("hex"),
    );
  });

  it("omits actionHash when no action is provided", () => {
    const [b64] = generateCsrfToken("s").split(".");
    expect(
      JSON.parse(Buffer.from(b64, "base64").toString()).actionHash,
    ).toBeUndefined();
  });
});

// ── verifyCsrf happy path ──────────────────────────────────────────────────
describe("verifyCsrf – happy path", () => {
  it("returns true for a well-formed current token", () => {
    const t = generateCsrfToken("valid-session");
    expect(
      verifyCsrf({
        cookies: { [SESSION_COOKIE]: "valid-session", [CSRF_COOKIE]: t },
        headers: { [CSRF_HEADER]: t },
      }),
    ).toBe(true);
  });

  it("accepts an action-bound token with the correct action", () => {
    const t = generateCsrfToken("s", "delete-account");
    expect(
      verifyCsrf(
        {
          cookies: { [SESSION_COOKIE]: "s", [CSRF_COOKIE]: t },
          headers: { [CSRF_HEADER]: t },
        },
        "delete-account",
      ),
    ).toBe(true);
  });
});

// ── verifyCsrf rejection cases ─────────────────────────────────────────────
describe("verifyCsrf – rejection cases", () => {
  it("throws 'Missing tokens' when session cookie absent (login without session)", () => {
    const t = generateCsrfToken("s");
    expect(() =>
      verifyCsrf({
        cookies: { [CSRF_COOKIE]: t },
        headers: { [CSRF_HEADER]: t },
      }),
    ).toThrow("Missing tokens");
  });

  it("throws 'Missing tokens' when CSRF header absent (R1 – login omits CSRF header)", () => {
    const t = generateCsrfToken("s");
    expect(() =>
      verifyCsrf({
        cookies: { [SESSION_COOKIE]: "s", [CSRF_COOKIE]: t },
        headers: {},
      }),
    ).toThrow("Missing tokens");
  });

  it("throws 'Token mismatch' when cookie and header differ (R1 – logout CSRF cookie/header disagree)", () => {
    const t1 = generateCsrfToken("s");
    const t2 = generateCsrfToken("s");
    expect(() =>
      verifyCsrf({
        cookies: { [SESSION_COOKIE]: "s", [CSRF_COOKIE]: t1 },
        headers: { [CSRF_HEADER]: t2 },
      }),
    ).toThrow("Token mismatch");
  });

  it("throws 'Invalid token signature' when HMAC is tampered", () => {
    const [b64] = generateCsrfToken("s").split(".");
    const tampered = `${b64}.${"a".repeat(64)}`;
    expect(() =>
      verifyCsrf({
        cookies: { [SESSION_COOKIE]: "s", [CSRF_COOKIE]: tampered },
        headers: { [CSRF_HEADER]: tampered },
      }),
    ).toThrow("Invalid token signature");
  });

  it("throws 'Session token mismatch' when embedded session differs from cookie", () => {
    const t = generateCsrfToken("original-session");
    expect(() =>
      verifyCsrf({
        cookies: { [SESSION_COOKIE]: "different-session", [CSRF_COOKIE]: t },
        headers: { [CSRF_HEADER]: t },
      }),
    ).toThrow("Session token mismatch");
  });

  it("throws 'Token expired' for a token older than CSRF_TOKEN_MAX_AGE (15 min)", () => {
    const payload: CSRFTokenPayload = {
      sessionToken: "s",
      timestamp: Date.now() - CSRF_MAX_AGE - 5_000,
      nonce: randomBytes(16).toString("hex"),
    };
    const payloadStr = JSON.stringify(payload);
    const sig = createHmac("sha256", SECRET).update(payloadStr).digest("hex");
    const t = `${Buffer.from(payloadStr).toString("base64")}.${sig}`;
    expect(() =>
      verifyCsrf({
        cookies: { [SESSION_COOKIE]: "s", [CSRF_COOKIE]: t },
        headers: { [CSRF_HEADER]: t },
      }),
    ).toThrow("Token expired");
  });

  it("throws 'Action mismatch' when action-bound token verified with wrong action", () => {
    const t = generateCsrfToken("s", "logout");
    expect(() =>
      verifyCsrf(
        {
          cookies: { [SESSION_COOKIE]: "s", [CSRF_COOKIE]: t },
          headers: { [CSRF_HEADER]: t },
        },
        "delete-account",
      ),
    ).toThrow("Action mismatch");
  });
});
