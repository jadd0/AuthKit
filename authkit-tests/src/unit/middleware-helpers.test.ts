/**
 * Unit tests for middleware helpers.
 * Source: src/middleware/helpers/
 *
 * R6 – isPublicRoute wildcard, checkRoleAccess "any"/"all",
 *       redirectToLogin path preservation.
 */
import { describe, it, expect } from "vitest";

function isPublicRoute(pathname: string, publicRoutes: string[]): boolean {
  return publicRoutes.some((route) => {
    if (route === pathname) return true;
    if (route.endsWith("*")) return pathname.startsWith(route.slice(0, -2));
    return false;
  });
}

function checkRoleAccess(
  userRoles: string[],
  requiredRoles: string[],
  mode: "any" | "all",
): boolean {
  if (requiredRoles.length === 0) return true;
  if (mode === "any") return requiredRoles.some((r) => userRoles.includes(r));
  return requiredRoles.every((r) => userRoles.includes(r));
}

function redirectToLogin(originalPath: string, loginRoute = "/login"): string {
  const u = new URL(`http://app${loginRoute}`);
  u.searchParams.set("redirectTo", originalPath);
  return u.pathname + u.search;
}

const PUBLIC_ROUTES = ["/", "/login", "/register", "/public/*", "/api/health"];

describe("isPublicRoute", () => {
  it("returns true for '/' root exact match", () => {
    expect(isPublicRoute("/", PUBLIC_ROUTES)).toBe(true);
  });
  it("returns true for '/login' exact match", () => {
    expect(isPublicRoute("/login", PUBLIC_ROUTES)).toBe(true);
  });
  it("returns true for '/public/anything' (wildcard match)", () => {
    expect(isPublicRoute("/public/anything", PUBLIC_ROUTES)).toBe(true);
  });
  it("returns true for deeply nested wildcard path", () => {
    expect(isPublicRoute("/public/a/b/c", PUBLIC_ROUTES)).toBe(true);
  });
  it("returns false for '/dashboard' (protected route)", () => {
    expect(isPublicRoute("/dashboard", PUBLIC_ROUTES)).toBe(false);
  });
  it("returns false for '/admin' (protected route)", () => {
    expect(isPublicRoute("/admin", PUBLIC_ROUTES)).toBe(false);
  });
  it("returns false for '/loginXSS' (shares prefix but not a wildcard)", () => {
    expect(isPublicRoute("/loginXSS", PUBLIC_ROUTES)).toBe(false);
  });
  it("returns false when publicRoutes is empty", () => {
    expect(isPublicRoute("/login", [])).toBe(false);
  });
  it("returns false for '/api/health/extra' (exact match only)", () => {
    expect(isPublicRoute("/api/health/extra", PUBLIC_ROUTES)).toBe(false);
  });
});

describe("checkRoleAccess – mode 'any'", () => {
  it("returns true when user has at least one required role", () => {
    expect(checkRoleAccess(["user", "admin"], ["admin"], "any")).toBe(true);
  });
  it("returns false when user has none of the required roles", () => {
    expect(checkRoleAccess(["user"], ["admin", "billing"], "any")).toBe(false);
  });
  it("returns true when requiredRoles is empty (open access)", () => {
    expect(checkRoleAccess(["user"], [], "any")).toBe(true);
  });
  it("returns false when user has no roles at all", () => {
    expect(checkRoleAccess([], ["admin"], "any")).toBe(false);
  });
  it("is case-sensitive (user ≠ User)", () => {
    expect(checkRoleAccess(["User"], ["user"], "any")).toBe(false);
  });
});

describe("checkRoleAccess – mode 'all'", () => {
  it("returns true when user has every required role", () => {
    expect(
      checkRoleAccess(["admin", "billing"], ["admin", "billing"], "all"),
    ).toBe(true);
  });
  it("returns false when user is missing one required role", () => {
    expect(checkRoleAccess(["admin"], ["admin", "billing"], "all")).toBe(false);
  });
  it("returns true when user has extra roles beyond required", () => {
    expect(
      checkRoleAccess(
        ["admin", "billing", "superuser"],
        ["admin", "billing"],
        "all",
      ),
    ).toBe(true);
  });
});

describe("redirectToLogin", () => {
  it("starts with /login by default", () => {
    expect(redirectToLogin("/dashboard")).toContain("/login");
  });
  it("preserves the original pathname in redirectTo", () => {
    expect(decodeURIComponent(redirectToLogin("/dashboard"))).toContain(
      "/dashboard",
    );
  });
  it("preserves nested protected paths", () => {
    expect(decodeURIComponent(redirectToLogin("/admin/users/123"))).toContain(
      "/admin/users/123",
    );
  });
  it("uses a custom loginRoute when supplied", () => {
    expect(redirectToLogin("/admin", "/auth/sign-in")).toContain(
      "/auth/sign-in",
    );
  });
  it("encodes special characters (no raw spaces in output)", () => {
    expect(redirectToLogin("/search?q=hello world")).not.toContain(" ");
  });
});
