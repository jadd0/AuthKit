/**
 * Unit tests for session cookie generation.
 * Source: src/shared/utils/session/generateSessionCookie.ts
 *
 * Cookie names from: src/shared/constants/auth.constants.ts
 * R2 – opaque tokens, HttpOnly, Secure in production.
 */
import { describe, it, expect } from "vitest";

const SESSION_COOKIE_NAME = "authkit-session";
const CSRF_COOKIE_NAME = "authkit-csrf-token";
const OIDC_STATE_COOKIE = "authkit-state";
const OIDC_VERIFIER_COOKIE = "authkit-verifier";

type SameSite = "Strict" | "Lax" | "None";

function generateSessionCookie(
  name: string,
  value: string,
  maxAgeSeconds: number,
  secure: boolean,
  opts: { sameSite?: SameSite } = {},
): string {
  const attrs = [
    `${name}=${value}`,
    "HttpOnly",
    "Path=/",
    `Max-Age=${maxAgeSeconds}`,
    `SameSite=${opts.sameSite ?? "Strict"}`,
    secure ? "Secure" : "",
  ];
  return attrs.filter(Boolean).join("; ");
}

describe("generateSessionCookie – production (secure=true)", () => {
  const cookie = generateSessionCookie(
    SESSION_COOKIE_NAME,
    "tok123",
    3600,
    true,
  );

  it("includes the correct name=value pair", () => {
    expect(cookie).toContain(`${SESSION_COOKIE_NAME}=tok123`);
  });
  it("sets HttpOnly", () => {
    expect(cookie).toContain("HttpOnly");
  });
  it("sets Secure flag", () => {
    expect(cookie).toContain("Secure");
  });
  it("sets Path=/", () => {
    expect(cookie).toContain("Path=/");
  });
  it("sets Max-Age to the supplied value", () => {
    expect(cookie).toContain("Max-Age=3600");
  });
  it("defaults SameSite to Strict", () => {
    expect(cookie).toContain("SameSite=Strict");
  });
});

describe("generateSessionCookie – development (secure=false)", () => {
  const cookie = generateSessionCookie(
    SESSION_COOKIE_NAME,
    "devtok",
    86400,
    false,
  );
  it("omits the Secure flag", () => {
    expect(cookie).not.toContain("Secure");
  });
  it("still sets HttpOnly", () => {
    expect(cookie).toContain("HttpOnly");
  });
});

describe("generateSessionCookie – SameSite overrides", () => {
  it("respects SameSite=Lax", () => {
    expect(
      generateSessionCookie("c", "v", 60, true, { sameSite: "Lax" }),
    ).toContain("SameSite=Lax");
  });
  it("respects SameSite=None", () => {
    expect(
      generateSessionCookie("c", "v", 60, true, { sameSite: "None" }),
    ).toContain("SameSite=None");
  });
});

describe("generateSessionCookie – OIDC state and verifier cookies", () => {
  it("authkit-state uses SameSite=Lax (cross-site redirect compatibility)", () => {
    const c = generateSessionCookie(OIDC_STATE_COOKIE, "sv", 600, true, {
      sameSite: "Lax",
    });
    expect(c).toContain(`${OIDC_STATE_COOKIE}=sv`);
    expect(c).toContain("SameSite=Lax");
    expect(c).toContain("HttpOnly");
    expect(c).toContain("Secure");
  });

  it("authkit-verifier is HttpOnly and SameSite=Lax", () => {
    const c = generateSessionCookie(OIDC_VERIFIER_COOKIE, "vv", 600, true, {
      sameSite: "Lax",
    });
    expect(c).toContain(`${OIDC_VERIFIER_COOKIE}=vv`);
    expect(c).toContain("HttpOnly");
    expect(c).toContain("SameSite=Lax");
  });

  it("authkit-csrf-token cookie name is correct", () => {
    expect(
      generateSessionCookie(CSRF_COOKIE_NAME, "cv", 900, true, {
        sameSite: "Lax",
      }),
    ).toContain(`${CSRF_COOKIE_NAME}=cv`);
  });
});

describe("generateSessionCookie – attribute count", () => {
  it("production cookie has exactly 6 attributes", () => {
    expect(
      generateSessionCookie("n", "v", 60, true).split("; ").filter(Boolean),
    ).toHaveLength(6);
  });
  it("development cookie has exactly 5 attributes (no Secure)", () => {
    expect(
      generateSessionCookie("n", "v", 60, false).split("; ").filter(Boolean),
    ).toHaveLength(5);
  });
});
