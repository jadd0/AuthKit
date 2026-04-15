import { generateSessionCookieObject } from "@/shared/utils/session";
import { auth as getAuthFn } from "./auth";
import { getAuthConfig, getAuth } from "@/server/core/singleton";
import { DEFAULT_IDLE_TTL } from "@/shared/constants/config.constants";
import { cookies } from "next/headers";
import { SESSION_COOKIE_NAME } from "@/shared/constants/auth.constants";

/**
 * Rotates the current user session, and returns a function to set the new session cookie.
 */
export async function rotateSession() {
  const authObject = getAuth();
  const authConfig = getAuthConfig();

  // Get the current session
  const session = await getAuthFn();

  // No active session for the given user
  if (!session) {
    throw new Error("No active session found.");
  }

  // Rotate the session
  const rotatedSession = await authObject?.sessions.rotateSession(session.id);

  // Error occurred whilst rotating session
  if (!rotatedSession) {
    throw new Error("Failed to rotate session.");
  }


  // Generate session cookie object
  const cookieConfig = generateSessionCookieObject(
    SESSION_COOKIE_NAME,
    rotatedSession.getSessionToken(),
    authConfig?.options.idleTTL || DEFAULT_IDLE_TTL,
    true,
  );

  // Return the rotated session and a function to set the cookie
  return {
    session: rotatedSession,
    setCookie: async () => {
      const cookieStore = await cookies();
      cookieStore.set(cookieConfig);
    },
  };
}
