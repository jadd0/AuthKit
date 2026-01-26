import { auth as getAuth } from "./auth";
import { auth } from "@/server/core/singleton";

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

  // Return the rotated session
  return rotatedSession;
}
