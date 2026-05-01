import { describe, it, expect, vi, beforeEach } from "vitest";

type NextResult = {
  type: "next";
  status: number;
};

type RedirectResult = {
  type: "redirect";
  status: number;
  location: string;
};

type MiddlewareResult = NextResult | RedirectResult;

type RoleRule = {
  pattern: RegExp;
  requiredRoles: string[];
  mode?: "any" | "all";
};

interface MiddlewareConfig {
  publicRoutes?: string[];
  loginRoute?: string;
  roleRules?: RoleRule[];
}

const SESSION_COOKIE_NAME = "authkit_session";
const DEFAULT_PUBLIC_ROUTES = ["/", "/login", "/register"];

function isPublicRoute(pathname: string, publicRoutes: string[]): boolean {
  return publicRoutes.some((route) => {
    if (route === pathname) return true;

    if (route.endsWith("/*")) {
      const prefix = route.slice(0, -2);
      return pathname.startsWith(prefix);
    }

    return false;
  });
}

function checkRoleAccess(
  userRoles: string[],
  requiredRoles: string[],
  mode: "any" | "all",
): boolean {
  if (requiredRoles.length === 0) return true;

  if (mode === "any") {
    return requiredRoles.some((role) => userRoles.includes(role));
  }

  return requiredRoles.every((role) => userRoles.includes(role));
}

function redirectToLogin(
  request: FakeRequest,
  loginRoute: string,
  originalPath: string,
): RedirectResult {
  const url = new URL(request.nextUrl.toString());
  url.pathname = loginRoute;
  url.search = "";
  url.searchParams.set("redirectTo", originalPath);

  return {
    type: "redirect",
    status: 307,
    location: `${url.pathname}${url.search}`,
  };
}

function next(): NextResult {
  return {
    type: "next",
    status: 200,
  };
}

function expectRedirect(res: MiddlewareResult): asserts res is RedirectResult {
  expect(res.type).toBe("redirect");
  if (res.type !== "redirect") {
    throw new Error("Expected redirect response");
  }
}

type FakeRequest = {
  nextUrl: URL;
  cookies: {
    get(name: string): { value: string } | undefined;
  };
};

function makeRequest(
  pathname: string,
  cookies: Record<string, string> = {},
): FakeRequest {
  const url = new URL(`https://app.example.com${pathname}`);

  return {
    nextUrl: url,
    cookies: {
      get(name: string) {
        const value = cookies[name];
        return value ? { value } : undefined;
      },
    },
  };
}

function withAuthMiddleware(
  config: MiddlewareConfig = {},
  deps?: {
    getAuthInstance?: () => Promise<any>;
    logger?: { info: (...args: any[]) => void };
  },
) {
  const {
    publicRoutes = DEFAULT_PUBLIC_ROUTES,
    loginRoute = "/login",
    roleRules = [],
  } = config;

  const getAuthInstance = deps?.getAuthInstance ?? (async () => undefined);
  const logger = deps?.logger ?? { info: () => {} };

  return async function middleware(
    req: FakeRequest,
  ): Promise<MiddlewareResult> {
    const { pathname } = req.nextUrl;

    if (isPublicRoute(pathname, publicRoutes)) {
      return next();
    }

    if (pathname === loginRoute) {
      return next();
    }

    const sessionToken = req.cookies.get(SESSION_COOKIE_NAME)?.value;
    if (!sessionToken) {
      return redirectToLogin(req, loginRoute, pathname);
    }

    try {
      const auth = await getAuthInstance();

      if (auth?.sessions) {
        const session = await auth.sessions.getSessionByToken(sessionToken);

        if (!session) {
          return redirectToLogin(req, loginRoute, pathname);
        }

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
    } catch {
      logger.info(
        "Auth singleton not ready, deferring validation to route handler",
      );
    }

    return next();
  };
}

describe("withAuthMiddleware", () => {
  const logger = { info: vi.fn() };
  const getAuthInstance = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("short-circuits public routes without touching the singleton", async () => {
    const middleware = withAuthMiddleware(
      { publicRoutes: ["/public/*", "/login"] },
      { getAuthInstance, logger },
    );

    const res = await middleware(makeRequest("/public/docs"));

    expect(res).toEqual({ type: "next", status: 200 });
    expect(getAuthInstance).not.toHaveBeenCalled();
  });

  it("prevents login-route loops by allowing the login route through", async () => {
    const middleware = withAuthMiddleware(
      { publicRoutes: [], loginRoute: "/login" },
      { getAuthInstance, logger },
    );

    const res = await middleware(makeRequest("/login"));

    expect(res).toEqual({ type: "next", status: 200 });
    expect(getAuthInstance).not.toHaveBeenCalled();
  });

  it("redirects unauthenticated requests to /login and preserves the original path", async () => {
    const middleware = withAuthMiddleware(
      { publicRoutes: [], loginRoute: "/login" },
      { getAuthInstance, logger },
    );

    const res = await middleware(makeRequest("/admin/users"));

    expectRedirect(res);
    expect(res.location).toBe("/login?redirectTo=%2Fadmin%2Fusers");
    expect(getAuthInstance).not.toHaveBeenCalled();
  });

  it("redirects when a session cookie exists but no session is found", async () => {
    getAuthInstance.mockResolvedValue({
      sessions: {
        getSessionByToken: vi.fn().mockResolvedValue(null),
      },
    });

    const middleware = withAuthMiddleware(
      { publicRoutes: [], loginRoute: "/login" },
      { getAuthInstance, logger },
    );

    const res = await middleware(
      makeRequest("/billing", { [SESSION_COOKIE_NAME]: "stolen-or-expired" }),
    );

    expectRedirect(res);
    expect(res.location).toBe("/login?redirectTo=%2Fbilling");
  });

  it("allows the request when the singleton is unavailable but a session cookie exists", async () => {
    getAuthInstance.mockRejectedValue(new Error("not initialised"));

    const middleware = withAuthMiddleware(
      { publicRoutes: [], loginRoute: "/login" },
      { getAuthInstance, logger },
    );

    const res = await middleware(
      makeRequest("/dashboard", { [SESSION_COOKIE_NAME]: "cookie-present" }),
    );

    expect(res).toEqual({ type: "next", status: 200 });
    expect(logger.info).toHaveBeenCalledTimes(1);
  });

  it('allows access when a role rule in "any" mode matches at least one user role', async () => {
    getAuthInstance.mockResolvedValue({
      sessions: {
        getSessionByToken: vi.fn().mockResolvedValue({
          user: { roles: ["user", "billing"] },
        }),
      },
    });

    const middleware = withAuthMiddleware(
      {
        publicRoutes: [],
        loginRoute: "/login",
        roleRules: [
          {
            pattern: /^\/billing/,
            requiredRoles: ["admin", "billing"],
            mode: "any",
          },
        ],
      },
      { getAuthInstance, logger },
    );

    const res = await middleware(
      makeRequest("/billing/invoices", {
        [SESSION_COOKIE_NAME]: "valid-token",
      }),
    );

    expect(res).toEqual({ type: "next", status: 200 });
  });

  it('redirects access when a role rule in "any" mode matches no user role', async () => {
    getAuthInstance.mockResolvedValue({
      sessions: {
        getSessionByToken: vi.fn().mockResolvedValue({
          user: { roles: ["user"] },
        }),
      },
    });

    const middleware = withAuthMiddleware(
      {
        publicRoutes: [],
        loginRoute: "/login",
        roleRules: [
          {
            pattern: /^\/billing/,
            requiredRoles: ["admin", "billing"],
            mode: "any",
          },
        ],
      },
      { getAuthInstance, logger },
    );

    const res = await middleware(
      makeRequest("/billing", { [SESSION_COOKIE_NAME]: "valid-token" }),
    );

    expectRedirect(res);
    expect(res.location).toBe("/login?redirectTo=%2Fbilling");
  });

  it('allows access when a role rule in "all" mode is fully satisfied', async () => {
    getAuthInstance.mockResolvedValue({
      sessions: {
        getSessionByToken: vi.fn().mockResolvedValue({
          user: { roles: ["admin", "billing", "user"] },
        }),
      },
    });

    const middleware = withAuthMiddleware(
      {
        publicRoutes: [],
        loginRoute: "/login",
        roleRules: [
          {
            pattern: /^\/admin/,
            requiredRoles: ["admin", "billing"],
            mode: "all",
          },
        ],
      },
      { getAuthInstance, logger },
    );

    const res = await middleware(
      makeRequest("/admin/reports", { [SESSION_COOKIE_NAME]: "valid-token" }),
    );

    expect(res).toEqual({ type: "next", status: 200 });
  });

  it('redirects access when a role rule in "all" mode is missing one required role', async () => {
    getAuthInstance.mockResolvedValue({
      sessions: {
        getSessionByToken: vi.fn().mockResolvedValue({
          user: { roles: ["admin"] },
        }),
      },
    });

    const middleware = withAuthMiddleware(
      {
        publicRoutes: [],
        loginRoute: "/login",
        roleRules: [
          {
            pattern: /^\/admin/,
            requiredRoles: ["admin", "billing"],
            mode: "all",
          },
        ],
      },
      { getAuthInstance, logger },
    );

    const res = await middleware(
      makeRequest("/admin/reports", { [SESSION_COOKIE_NAME]: "valid-token" }),
    );

    expectRedirect(res);
    expect(res.location).toBe("/login?redirectTo=%2Fadmin%2Freports");
  });
});
