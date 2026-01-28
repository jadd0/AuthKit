"use server";

import { generateSessionCookieObject } from "@/shared/utils/session";
import { auth as getAuth } from "./auth";
import { auth, authConfig } from "@/server/core/singleton";
import { DEFAULT_IDLE_TTL } from "@/shared/constants/config.constants";
import { cookies } from "next/headers";

/**
 * Rotates the current user session.
 */
export async function rotateSession() {
  // Get the current session
  const session = await getAuth();

  // No active session for the given user
  if (!session) {
    throw new Error("No active session found.");
  }

  // Rotate the session
  const rotatedSession = await auth.sessions.rotateSession(session.id);

  // Error occurred whilst rotating session
  if (!rotatedSession) {
    throw new Error("Failed to rotate session.");
  }

  // Generate session cookie object
  const cookie = generateSessionCookieObject(
    "session",
    rotatedSession.getSessionToken(),
    authConfig.options.idleTTL || DEFAULT_IDLE_TTL,
    true,
  );

  // Set the cookie in the response
  const cookieStore = await cookies();
  cookieStore.set(cookie);

  // Return the rotated session
  return rotatedSession;
}
