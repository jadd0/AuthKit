import { DatabaseUserInteractions } from "@/server/db/interfaces/databaseUserInteractions";
import { auth as getAuth } from "./auth";
import { auth } from "@/server/core/singleton";
import { SessionWithUser } from "@/shared/types";
import { Session } from "@/server/db/schemas/sessions.schemas";

/**
 * Function to update user privilege
 */
export async function updatePrivilege(
  roles: string[],
): Promise<SessionWithUser | null> {
  // Retrieves the current session
  const session = await getAuth();

  // No active session for the given user
  if (!session) {
    throw new Error("No active session found.");
  }

  // Update the user's role in the database
  const updatedUser = await DatabaseUserInteractions.updateUserRole(
    roles,
    session.user.id,
  );

  // Rotate the session to get updated privileges
  const updatedSession = await auth.sessions.rotateSession(session.id);

  if (!updatedSession) {
    throw new Error("Failed to rotate session for updated privileges.");
  }

  return updatedSession;
}
