import { auth, authConfig } from "@/server/core/singleton";
import { DEFAULT_IDLE_TTL } from "@/shared/constants";
import { generateSessionCookie } from "@/shared/utils/session";
import z from "zod";

export class ServerSession {
  constructor() {}

  /** Use this to get a session by its token, called from route handler after being invoked by clientSession */
  async getSession(token: string) {
    // Basic validation
    if (z.string().min(1).parse(token).length === 0) {
      throw new Error("Token is required");
    }

    // Attempt to retrieve the session by its token
    const session = auth.sessions.getSessionByToken(token);

    // Session not found
    if (!session) {
      throw new Error("Session not found or invalid token");
    }

    // Update last activity time for idle TTL
    const result = await session.updateLastActivityTime();

    if (!result) {
      throw new Error("Failed to update session activity time");
    }

    // Generate session cookie
    const cookie = generateSessionCookie(
      "session",
      session.getSessionToken(),
      authConfig.options.idleTTL || DEFAULT_IDLE_TTL
    );

    return { session, cookie };
  }
}
