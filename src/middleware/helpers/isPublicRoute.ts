/**
 * Check if a path matches public route patterns
 */
export function isPublicRoute(
  pathname: string,
  publicRoutes: string[],
): boolean {
  return publicRoutes.some((route) => {
    // Exact match
    if (route === pathname) return true;

    // Wildcard match: "/api/public/*" matches "/api/public/anything"
    if (route.endsWith("/*")) {
      const prefix = route.slice(0, -2);
      return pathname.startsWith(prefix);
    }

    return false;
  });
}
