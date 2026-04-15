import { getAuth, getAuthConfig } from "@/server/core/singleton";
import { DEFAULT_IDLE_TTL, SESSION_COOKIE_NAME } from "@/shared/constants";
import { generateCSRFCookie } from "@/shared/utils/CSRF/generateCSRFCookie";
import { generateCsrfToken } from "@/shared/utils/CSRF/generateCSRFToken";
import { generateSessionCookie } from "@/shared/utils/session";
import z from "zod";

export class ServerSession {
  constructor() {}

  /** Use this to get a session by its token, called from route handler after being invoked by clientSession */
  async getSession(token: string) {
    const auth = getAuth();
    const authConfig = getAuthConfig();

    // Basic validation
    if (z.string().min(1).parse(token).length === 0) {
      throw new Error("Token is required");
    }

    // Attempt to retrieve the session by its token
    const session = await auth?.sessions.getSessionByToken(token);

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
      SESSION_COOKIE_NAME,
      session.getSessionToken(),
      authConfig?.options.idleTTL || DEFAULT_IDLE_TTL,
    );

    const csrfToken = generateCsrfToken(session.getSessionToken());
    const csrfCookie = generateCSRFCookie(csrfToken);

    return { session, cookie, csrfCookie };
  }

  /** Use this to delete a session by its token, called from route handler after being invoked by clientSession */
  async deleteSession(token: string) {
    const auth = getAuth();
    const authConfig = getAuthConfig();

    // Basic validation
    if (z.string().min(1).parse(token).length === 0) {
      throw new Error("Token is required");
    }

    // Attempt to retrieve the session by its token
    const session = await auth?.sessions.getSessionByToken(token);

    // Session not found
    if (!session) {
      return false;
    }

    // Delete the session
    const result = await auth?.sessions.deleteSession(session.id);

    return result;
  }
}
