import { NextRequest, NextResponse } from "next/server";
import {
  checkRoleAccess,
  isPublicRoute,
  redirectToLogin,
} from "@/middleware/helpers";
import { SESSION_COOKIE_NAME } from "@/shared/constants";
import { logger } from "@/server/classes/AuthKitLogger";

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

    try {
      const { getAuthInstance } = await import("@/server/core/singleton");
      const auth = await getAuthInstance();

      if (auth?.sessions) {
        const session = await auth.sessions.getSessionByToken(sessionToken);

        if (!session) {
          return redirectToLogin(req, loginRoute, pathname);
        }

        // Check role-based access
        if (session.user && roleRules.length > 0) {
          for (const rule of roleRules) {
            if (rule.pattern.test(pathname)) {
              const hasAccess = checkRoleAccess(
                session.user.roles || [],
                rule.requiredRoles,
                rule.mode || "any",
              );

              if (!hasAccess) {
                return redirectToLogin(req, loginRoute, pathname);
              }
            }
          }
        }
      }
    } catch (error) {
      // Singleton not initialized yet - just allow through with cookie check
      // Route handlers will do full validation
      logger.info(
        "Auth singleton not ready, deferring validation to route handler",
      );
    }

    // User has cookie (and session if singleton was ready)
    return NextResponse.next();
  };
}
