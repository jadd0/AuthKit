import { Session } from "@/server/classes/auth/session";
import type { AuthConfig } from "@/shared/types";

/** Function used to run whatever callback is supplied in the auth.ts providers config */
export async function runCallback(
  config: AuthConfig,
  ctx: unknown,
  credentials: unknown
): Promise<Session | null> {
  // Gets the callback function from the config
  const fn = config.callbacks?.authorise as
    | ((ctx: unknown, credentials: unknown) => Promise<Session | null>)
    | undefined;
  // If no function is provided, return null
  if (!fn) return null;

  try {
    // Run the function with the provided context and credentials
    const result = await fn(ctx, credentials);

    // Validate the result to ensure it matches the expected structure
    if (
      result === null ||
      (typeof result === "object" &&
        result !== null &&
        "userId" in result &&
        typeof (result as any).userId === "string")
    ) {
      return result;
    }

    // The result was not validated, return null
    return null;
  } catch (e) {
    // If an error occurs, log it and return null
    console.error("Error in authorisation callback:", e);
    return null;
  }
}
