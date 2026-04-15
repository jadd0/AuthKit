import { CSRF_COOKIE_NAME } from "@/shared/constants";
import { getAuthConfig } from "@/server/core/singleton";

export function generateCSRFCookie(token: string): string {
	const authConfig = getAuthConfig();

  const isProduction = process.env.NODE_ENV === "production";

  const attributes = [
    `${CSRF_COOKIE_NAME}=${token}`,
    "Path=/",
    "SameSite=Lax",
    isProduction ? "Secure" : "",
  ];

  if (authConfig?.options.idleTTL) {
    const maxAgeSeconds = Math.floor(authConfig.options.idleTTL / 1000);
    attributes.push(`Max-Age=${maxAgeSeconds}`);
  }

  return attributes.filter(Boolean).join("; ");
}
