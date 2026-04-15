import { getAuthConfig } from "@/server/core/singleton";

/**
 * Generates cookie options for a secure, HttpOnly session cookie
 */
export function generateSessionCookie(
  name: string,
  value: string,
  maxAgeSeconds: number,
  secure = true
) {
  const authConfig = getAuthConfig();

  return `${name}=${value}; HttpOnly; Path=/; Max-Age=${maxAgeSeconds}; SameSite=${
    authConfig?.options.sameSite || "Strict"
  }; ${secure ? "Secure;" : ""}`;
}
