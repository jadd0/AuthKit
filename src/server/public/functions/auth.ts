import { SessionWithUser } from "@/shared/types";
import { cookies } from "next/headers";
import { auth as authObject } from "@/server/core/singleton";

/** Public function for server-side auth, returns a user session */
export default async function auth(): Promise<SessionWithUser | null> {
  // Attempts to retrieve the session cookie token
  const cookieStore = await cookies();
  const token = cookieStore.get("session")?.value;

  // No token present
  if (!token) return null;

  try {
    const session = authObject.sessions.getSessionByToken(token);

    // No session found
    if (!session) {
      return null;
    }

    return session;
  } catch (error) {
    return null;
  }
}
