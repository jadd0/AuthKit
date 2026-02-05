import { NextRequest, NextResponse } from "next/server";
import {
  checkRoleAccess,
  isPublicRoute,
  redirectToLogin,
} from "@/middleware/helpers";
import { SESSION_COOKIE_NAME } from "@/shared/constants";

interface MiddlewareConfig {
  /**
   * Paths that do not require authentication. Can include wildcards (e.g. "/public/*") to match multiple routes.
   */
  publicRoutes?: string[];

  /* Optional custom login route for redirection when unauthenticated. Defaults to "/login". */
  loginRoute?: string;

  /**
   * Optional role-based rules
   * Example: [{ pattern: /^\/admin/, requiredRoles: ["admin"] }]
   * "any" means user must have at least one of the required roles (union), "all" means user must have all required roles (intersection)
   */
  roleRules?: Array<{
    pattern: RegExp;
    requiredRoles: string[];
    mode?: "any" | "all";
  }>;
}

const DEFAULT_PUBLIC_ROUTES = ["/", "/login", "/register"];

/**
 * Middleware to protect routes and enforce authentication and role-based access control.
 * Usage: export const middleware = withAuthMiddleware(config);
 */
export function withAuthMiddleware(config: MiddlewareConfig = {}) {
  const {
    publicRoutes = DEFAULT_PUBLIC_ROUTES,
    loginRoute = "/login",
    roleRules = [],
  } = config;

  /** Returned function for middleware */
  return async function middleware(req: NextRequest) {
    const { pathname } = req.nextUrl;

    // Check if route is public
    if (isPublicRoute(pathname, publicRoutes)) {
      return NextResponse.next();
    }

    // Prevents redirect loops
    if (pathname === loginRoute) {
      return NextResponse.next();
    }

    // Check for cookie first (cheap check before singleton access)
    const sessionToken = req.cookies.get(SESSION_COOKIE_NAME)?.value;
    if (!sessionToken) {
      return redirectToLogin(req, loginRoute, pathname);
    }

    // LAZY IMPORT: Only access singleton when actually needed
    // By this point, user's route handlers have already initialized it
    const { auth } = await import("@/server/core/singleton");

    // If singleton still not ready, fail safely
    if (!auth?.sessions) {
      console.warn(
        "Auth singleton not initialized, deferring to route handler",
      );
      return NextResponse.next();
    }

    // Check authentication
    const session = auth.sessions.getSessionByToken(sessionToken);

    // If no valid session, redirect to login
    if (!session) {
      return redirectToLogin(req, loginRoute, pathname);
    }

    // Check role-based access rules
    if (session.user && roleRules.length > 0) {
      for (const rule of roleRules) {
        if (rule.pattern.test(pathname)) {
          const hasAccess = checkRoleAccess(
            session.user.roles || [],
            rule.requiredRoles,
            rule.mode || "any",
          );

          if (!hasAccess) {
            // Unauthorized - redirect to login or 403 page
            return redirectToLogin(req, loginRoute, pathname);
          }
        }
      }
    }

    // User is authenticated and authorized, proceed to the route
    return NextResponse.next();
  };
}
