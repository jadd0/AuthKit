import { authConfig } from "@/server/core/singleton";
import { auth as getAuth } from "./auth";
import * as bcrypt from "bcrypt";
import { DatabaseAccountInteractions } from "@/server/db/interfaces/databaseAccountInteractions";
import { rotateSession } from "./rotateSession";

/** Updates a user's password. Returns the rotated session and a function to set the new session cookie. */
export async function updatePassword(newPassword: string) {
  // Get the current session
  const session = await getAuth();

  // No active session for the given user
  if (!session) {
    throw new Error("No active session found.");
  }

  // Hash the new password
  const hashedPassword = await bcrypt.hash(
    newPassword,
    authConfig.providers.find((p) => p.type === "credentials")!.saltingRounds!,
  );

  // Update the password in the database
  const result = await DatabaseAccountInteractions.updateAccountPassword(
    session.user.id,
    hashedPassword,
  );

  // Error occurred whilst updating password
  if (!result) {
    throw new Error("Failed to update password.");
  }

  // Rotate the session to reflect the password change
  const rotateResult = await rotateSession();

  // Error whilst rotating the session
  if (!rotateResult) {
    throw new Error("Failed to rotate session after password update.");
  }

  return rotateResult;
}
