/**
 * Check if user has required roles
 */
export function checkRoleAccess(
  userRoles: string[],
  requiredRoles: string[],
  mode: "any" | "all",
): boolean {
  if (requiredRoles.length === 0) return true;

  if (mode === "any") {
    return requiredRoles.some((role) => userRoles.includes(role));
  }

  // mode === 'all'
  return requiredRoles.every((role) => userRoles.includes(role));
}