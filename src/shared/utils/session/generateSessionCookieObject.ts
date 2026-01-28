import { authConfig } from "@/server/core/singleton";

/** Generates a session cookie object */
export function generateSessionCookieObject(
  name: string,
  value: string,
  maxAgeSeconds: number,
  secure = true
) {
  return {
    name,
    value,
    httpOnly: true,
    secure,
    maxAge: maxAgeSeconds,
    path: "/",
    sameSite: authConfig.options.sameSite || "strict",
  };
}