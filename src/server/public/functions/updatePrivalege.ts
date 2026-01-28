import { DatabaseUserInteractions } from "@/server/db/interfaces/databaseUserInteractions";
import { auth as getAuth } from "./auth";
import { auth } from "@/server/core/singleton";
import { SessionWithUser } from "@/shared/types";
import { authConfig } from "@/server/core/singleton";
import { rotateSession } from "./rotateSession";

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

  // Check that the user roles are valid
  const validRoles = authConfig.options.roles;
  if (validRoles) {
    for (const role of roles) {
      if (!validRoles.includes(role)) {
        throw new Error(`Invalid role: ${role}`);
      }
    }
  }

  // Update the user's role in the database
  const updatedUser = await DatabaseUserInteractions.updateUserRole(
    roles,
    session.user.id,
  );

  if (!updatedUser) {
    throw new Error("Failed to update user roles.");
  }

  // Rotate the session to get updated privileges
  const rotateResult = await rotateSession();

  // Error whilst rotating the session
  if (!rotateResult) {
    throw new Error("Failed to rotate session after privilege update.");
  }

  return rotateResult;
}
