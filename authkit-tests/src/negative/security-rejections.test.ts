import { describe, it, expect } from "vitest";
import { createHmac, createHash, randomBytes } from "crypto";

const SECRET = "test-csrf-secret-minimum-32-chars-ok!";
const SESSION_COOKIE = "authkit-session";
const CSRF_COOKIE = "authkit-csrf";
const CSRF_HEADER = "x-authkit-csrf";
const CSRF_TOKEN_MAX_AGE = 15 * 60 * 1000;

interface RequestShape {
  cookies: Record<string, string>;
  headers: Record<string, string>;
}

interface StatePayload {
  state: string;
  nonce: string;
  providerId: string;
  redirectTo?: string;
}

function generateCsrfToken(sessionToken: string): string {
  const payload = {
    sessionToken,
    timestamp: Date.now(),
  };

  const payloadJson = JSON.stringify(payload);
  const payloadB64 = Buffer.from(payloadJson).toString("base64");
  const signature = createHmac("sha256", SECRET)
    .update(payloadJson)
    .digest("hex");

  return `${payloadB64}.${signature}`;
}

function verifyCsrf(request: RequestShape): true {
  const sessionToken = request.cookies[SESSION_COOKIE];
  const csrfCookie = request.cookies[CSRF_COOKIE];
  const csrfHeader = request.headers[CSRF_HEADER];

  if (!sessionToken || !csrfCookie || !csrfHeader) {
    throw new Error("CSRF validation failed: Missing tokens");
  }

  if (csrfCookie !== csrfHeader) {
    throw new Error("CSRF validation failed: Token mismatch");
  }

  const [payloadB64, signature] = csrfHeader.split(".");

  if (!payloadB64 || !signature) {
    throw new Error("CSRF validation failed: Malformed token");
  }

  const payloadJson = Buffer.from(payloadB64, "base64").toString();
  const expectedSignature = createHmac("sha256", SECRET)
    .update(payloadJson)
    .digest("hex");

  if (expectedSignature !== signature) {
    throw new Error("CSRF validation failed: Invalid token signature");
  }

  const payload = JSON.parse(payloadJson) as {
    sessionToken: string;
    timestamp: number;
  };

  if (payload.sessionToken !== sessionToken) {
    throw new Error("CSRF validation failed: Session token mismatch");
  }

  if (Date.now() - payload.timestamp > CSRF_TOKEN_MAX_AGE) {
    throw new Error("CSRF validation failed: Token expired");
  }

  return true;
}

function validateRedirectUri(
  uri: string,
  allowList: string[],
  env: "development" | "production" = "production",
): { valid: boolean; reason?: string } {
  if (!uri) {
    return { valid: false, reason: "Redirect URI is required" };
  }

  let parsed: URL;

  try {
    parsed = new URL(uri);
  } catch {
    return { valid: false, reason: "Redirect URI is malformed" };
  }

  const isLocalhost = ["localhost", "127.0.0.1", "::1"].includes(
    parsed.hostname,
  );

  if (parsed.protocol === "http:" && !isLocalhost && env === "production") {
    return {
      valid: false,
      reason: "HTTP redirect URIs are not allowed in production",
    };
  }

  for (const allowed of allowList) {
    const allowedUrl = new URL(allowed);

    if (
      parsed.protocol === allowedUrl.protocol &&
      parsed.hostname === allowedUrl.hostname &&
      parsed.port === allowedUrl.port &&
      parsed.pathname === allowedUrl.pathname &&
      parsed.search === allowedUrl.search &&
      parsed.hash === allowedUrl.hash
    ) {
      return { valid: true };
    }
  }

  return {
    valid: false,
    reason: `Redirect URI ${uri} does not match any allowed redirect.`,
  };
}

function verifyPkce(codeVerifier: string, codeChallenge: string): boolean {
  if (!codeVerifier) return false;

  const derived = createHash("sha256").update(codeVerifier).digest("base64url");

  return derived === codeChallenge;
}

function signStatePayload(payload: StatePayload, secret = SECRET): string {
  const payloadJson = JSON.stringify(payload);
  const payloadB64 = Buffer.from(payloadJson).toString("base64");
  const signature = createHmac("sha256", secret)
    .update(payloadJson)
    .digest("hex");

  return `${payloadB64}.${signature}`;
}

function verifyStatePayload(signed: string): StatePayload | null {
  const [payloadB64, signature] = signed.split(".");

  if (!payloadB64 || !signature) {
    return null;
  }

  try {
    const payloadJson = Buffer.from(payloadB64, "base64").toString();
    const payload = JSON.parse(payloadJson) as StatePayload;
    const expectedSignature = createHmac("sha256", SECRET)
      .update(payloadJson)
      .digest("hex");

    return expectedSignature === signature ? payload : null;
  } catch {
    return null;
  }
}

function tokenLikeLogScanner(line: string): boolean {
  const patterns = [
    /sessionToken/i,
    /accessToken/i,
    /csrf/i,
    /Bearer\s+[A-Za-z0-9._-]{20,}/,
    /\b[a-f0-9]{64}\b/i,
    /\b[A-Za-z0-9\-_]{43}\b/,
  ];

  return patterns.some((pattern) => pattern.test(line));
}

const ALLOW_LIST = ["https://myapp.com/api/auth/provider/google/callback"];

describe("Redirect URI — attack vectors", () => {
  it("rejects open redirect with different hostname", () => {
    const result = validateRedirectUri(
      "https://evil.com/api/auth/provider/google/callback",
      ALLOW_LIST,
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toBeTruthy();
  });

  it("rejects protocol downgrade to http in production", () => {
    const result = validateRedirectUri(
      "http://myapp.com/api/auth/provider/google/callback",
      ALLOW_LIST,
      "production",
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toContain("HTTP redirect URIs are not allowed");
  });

  it("rejects port tampering", () => {
    const result = validateRedirectUri(
      "https://myapp.com:8443/api/auth/provider/google/callback",
      ALLOW_LIST,
    );

    expect(result.valid).toBe(false);
  });

  it("rejects query-string injection", () => {
    const result = validateRedirectUri(
      "https://myapp.com/api/auth/provider/google/callback?evil=true",
      ALLOW_LIST,
    );

    expect(result.valid).toBe(false);
  });

  it("rejects fragment injection", () => {
    const result = validateRedirectUri(
      "https://myapp.com/api/auth/provider/google/callback#fragment",
      ALLOW_LIST,
    );

    expect(result.valid).toBe(false);
  });

  it("rejects unapproved subdomain", () => {
    const result = validateRedirectUri(
      "https://sub.myapp.com/api/auth/provider/google/callback",
      ALLOW_LIST,
    );

    expect(result.valid).toBe(false);
  });
});

describe("PKCE — code_verifier attacks", () => {
  it("rejects missing verifier", () => {
    const realVerifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256")
      .update(realVerifier)
      .digest("base64url");

    expect(verifyPkce("", challenge)).toBe(false);
  });

  it("rejects mismatched verifier replayed from another session", () => {
    const verifierA = randomBytes(32).toString("base64url");
    const verifierB = randomBytes(32).toString("base64url");
    const challengeA = createHash("sha256")
      .update(verifierA)
      .digest("base64url");

    expect(verifyPkce(verifierB, challengeA)).toBe(false);
  });

  it("rejects truncated verifier", () => {
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");

    expect(verifyPkce(verifier.slice(0, 20), challenge)).toBe(false);
  });
});

describe("OIDC state — tampering attacks", () => {
  it("rejects fabricated signature", () => {
    const [payloadB64] = signStatePayload({
      state: "abc",
      nonce: "xyz",
      providerId: "google",
    }).split(".");

    expect(verifyStatePayload(`${payloadB64}.${"a".repeat(64)}`)).toBeNull();
  });

  it("rejects modified payload with reused signature", () => {
    const original = signStatePayload({
      state: "abc",
      nonce: "xyz",
      providerId: "google",
    });

    const [, originalSignature] = original.split(".");
    const tamperedPayloadB64 = Buffer.from(
      JSON.stringify({
        state: "evil",
        nonce: "xyz",
        providerId: "google",
      }),
    ).toString("base64");

    expect(
      verifyStatePayload(`${tamperedPayloadB64}.${originalSignature}`),
    ).toBeNull();
  });

  it("rejects state signed with the wrong secret", () => {
    const signedWithWrongSecret = signStatePayload(
      {
        state: "abc",
        nonce: "xyz",
        providerId: "google",
      },
      "wrong-secret",
    );

    expect(verifyStatePayload(signedWithWrongSecret)).toBeNull();
  });

  it("rejects empty state string", () => {
    expect(verifyStatePayload("")).toBeNull();
  });

  it("rejects state string without a dot separator", () => {
    expect(verifyStatePayload("not-a-valid-state")).toBeNull();
  });
});

describe("CSRF — rejection paths", () => {
  it("rejects login request without CSRF header", () => {
    const token = generateCsrfToken("session-1");

    expect(() =>
      verifyCsrf({
        cookies: {
          [SESSION_COOKIE]: "session-1",
          [CSRF_COOKIE]: token,
        },
        headers: {},
      }),
    ).toThrow("Missing tokens");
  });

  it("rejects logout request with mismatched CSRF cookie and header", () => {
    const cookieToken = generateCsrfToken("session-1");
    const [payloadB64] = cookieToken.split(".");
    const mismatchedHeaderToken = `${payloadB64}.${"b".repeat(64)}`;

    expect(() =>
      verifyCsrf({
        cookies: {
          [SESSION_COOKIE]: "session-1",
          [CSRF_COOKIE]: cookieToken,
        },
        headers: {
          [CSRF_HEADER]: mismatchedHeaderToken,
        },
      }),
    ).toThrow("Token mismatch");
  });

  it("rejects expired CSRF token", () => {
    const payload = {
      sessionToken: "session-1",
      timestamp: Date.now() - CSRF_TOKEN_MAX_AGE - 5000,
    };

    const payloadJson = JSON.stringify(payload);
    const payloadB64 = Buffer.from(payloadJson).toString("base64");
    const signature = createHmac("sha256", SECRET)
      .update(payloadJson)
      .digest("hex");
    const expiredToken = `${payloadB64}.${signature}`;

    expect(() =>
      verifyCsrf({
        cookies: {
          [SESSION_COOKIE]: "session-1",
          [CSRF_COOKIE]: expiredToken,
        },
        headers: {
          [CSRF_HEADER]: expiredToken,
        },
      }),
    ).toThrow("Token expired");
  });
});

describe("Token-in-log scanner", () => {
  it("flags a line containing sessionToken", () => {
    expect(tokenLikeLogScanner("User logged in, sessionToken=abc123")).toBe(
      true,
    );
  });

  it("flags a line containing a 64-character hex token", () => {
    expect(tokenLikeLogScanner(`token=${"a".repeat(64)}`)).toBe(true);
  });

  it("flags a line containing a Bearer token", () => {
    expect(
      tokenLikeLogScanner(
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
      ),
    ).toBe(true);
  });
});
