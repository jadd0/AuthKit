import { DatabaseSessionInteractions } from "@/server/db/interfaces/databaseSessionInteractions";
import { Session } from "./session";
import { Session as DatabaseSession } from "@/shared/schemas";
import { DatabaseUserInteractions } from "@/server/db/interfaces/databaseUserInteractions";
import { generateSessionToken } from "@/shared/utils/session/generateSessionToken";
import { authConfig } from "@/server/core/singleton";
import { logger } from "@/server/classes/AuthKitLogger";

/**
 * @class Sessions
 * @description Represents a blueprint for an object encapsulating user sessions in the authentication system.
 * @property {Map<string, Session>} sessionsById - A map storing active sessions by their IDs.
 * @property {Map<string, Session>} sessionsByToken - A map storing active sessions by their tokens.
 */
export class Sessions {
  // START: CREATE

  /** Main property containing the user sessions, keyed by session ID */
  sessionsById: Map<string, Session>; // string "id" is directly equivalent to the database ID for a user's Session

  /** Secondary property for fast lookup by session token */
  sessionsByToken: Map<string, Session>;

  constructor() {
    this.sessionsById = new Map<string, Session>();
    this.sessionsByToken = new Map<string, Session>();

    // Cleanup old entries every 5 minutes
    setInterval(
      async () => {
        await this.deleteExpiredSessions();
      },
      2 * 60 * 1000, // 2 minutes in ms
    );
  }

  /** Create a new session (in database first) and store it in both maps */
  async createSession(user: any): Promise<Session> {
    // Generate a unique Session token
    const sessionToken = generateSessionToken();

    // Insert new session into Sessions database table
    const result = await DatabaseSessionInteractions.createSession({
      sessionToken: sessionToken,
      userId: user.id,
    });

    // DB error occurred
    if (!result) {
      throw new Error(
        "An error occurred whilst attempting to create a database authentication session for the user with ID: " +
          user.id,
      );
    }

    // Create server Session object
    const session = new Session({
      id: result.id,
      user,
      createdAt: result.createdAt,
      sessionToken,
    });

    // Append the new Session to both maps
    this.sessionsById.set(result.id, session);
    this.sessionsByToken.set(sessionToken, session);

    return session;
  }

  // END: CREATE

  // START: READ

  /** Retrieve a session by its ID */
  getSession(sessionId: string, updateActivity = true): Session | null {
    const session = this.sessionsById.get(sessionId);

    if (!session) {
      return null;
    }

    // Check if session is still valid
    if (!this.checkSessionValidity(session)) {
      return null;
    }

    // Update activity is true if true
    if (updateActivity) {
      this.maybeUpdateActivity(session);
    }

    return session;
  }

  /** Retrieve a session by its token, O(1) lookup */
  getSessionByToken(token: string): Session | null {
    const session = this.sessionsByToken.get(token);

    if (!session) {
      return null;
    }

    // Check if session is still valid

    if (!this.checkSessionValidity(session)) {
      return null;
    }

    return session;
  }

  // END: READ

  // START: UPDATE

  /** Method used to append database User Sessions to server-friendly maps */
  async appendDatabaseSessions(databaseSessions: DatabaseSession[]) {
    // Programmatically append each User to a Session object
    for (const session of databaseSessions) {
      // Remove expired sessions
      const now = Date.now();
      const absoluteTTL = authConfig.options.absoluteTTL;

      if (absoluteTTL) {
        const sessionAge = now - session.createdAt.getTime();
        if (sessionAge > absoluteTTL) {
          // Delete expired session from DB
          try {
            await DatabaseSessionInteractions.deleteSessionBySessionId(
              session.id,
            );
          } catch (error) {
            logger.error(
              "Error deleting expired session with ID " +
                session.id +
                " from database:",
              error,
            );
          }
          continue; // Skip to next session
        }
      }

      // Retrieve the user associated with the session userId
      const user = await DatabaseUserInteractions.getUserById(session.userId);

      if (!user) {
        throw new Error(
          "There has been an error whilst attempting to retrieve user with ID " +
            session.userId +
            " for the session with ID " +
            session.id +
            " when attempting to append database Session to server Session map.",
        );
      }

      // Append the session to both maps
      const sessionObj = new Session({
        id: session.id,
        user,
        createdAt: session.createdAt,
        sessionToken: session.sessionToken,
      });

      this.sessionsById.set(session.id, sessionObj);
      this.sessionsByToken.set(session.sessionToken, sessionObj);
    }

    logger.info(
      `Successfully appended ${this.sessionsById.size} database sessions to server session maps`,
    );
  }

  /**
   * Rotate session token and update both maps
   */
  async rotateSession(sessionId: string): Promise<Session | null> {
    const session = this.sessionsById.get(sessionId);
    if (!session) return null;

    // Remove old session from maps
    this.sessionsByToken.delete(session.getSessionToken());

    // Rotate on the session instance (updates DB)
    const newSession = await session.rotateSession();

    // Re-index with new token
    this.sessionsByToken.set(newSession.getSessionToken(), newSession);
    this.sessionsById.set(newSession.id, newSession);

    return newSession;
  }

  // END: UPDATE

  // START: DELETE

  /** Delete a session by its ID from both maps and the database */
  async deleteSession(sessionId: string): Promise<Boolean> {
    const session = this.sessionsById.get(sessionId);
    if (session) {
      this.sessionsByToken.delete(session.getSessionToken());
      this.sessionsById.delete(sessionId);
    }

    // Delete from DB
    if (
      !(await DatabaseSessionInteractions.deleteSessionBySessionId(sessionId))
    ) {
      logger.error(
        "An error occurred whilst attempting to delete the session with ID: " +
          sessionId +
          " from the database.",
      );
    }

    return true;
  }

  /** Method to delete all expired sessions */
  async deleteExpiredSessions() {
    const { absoluteTTL, idleTTL } = authConfig.options;

    // Delete from database in bulk
    const deletedCount =
      await DatabaseSessionInteractions.deleteExpiredSessions(
        absoluteTTL!,
        idleTTL!,
      );

    // Remove from in-memory maps
    if (deletedCount > 0) {
      for (const [id, session] of this.sessionsById.entries()) {
        const isExpired = await this.checkSessionValidity(session, false);

        if (!isExpired) {
          this.sessionsById.delete(id);
          this.sessionsByToken.delete(session.getSessionToken());
        }
      }
    }

    logger.info(`Deleted ${deletedCount} expired sessions from database`);
  }

  // END: DELETE

  // START: PRIVATE

  /** Private method used to delete a session by its token */
  private async deleteSessionByToken(
    token: string,
    deleteFromDB = true,
  ): Promise<void> {
    const session = this.sessionsByToken.get(token);

    if (session) {
      this.sessionsById.delete(session.id);
      this.sessionsByToken.delete(token);
    }

    // Delete from DB if true
    if (deleteFromDB) {
      const deleteResult = DatabaseSessionInteractions.deleteSessionBySessionId(
        session!.id,
      );

      if (!deleteResult) {
        throw new Error(
          "An error occurred whilst attempting to delete the session with token: " +
            token +
            " from the database.",
        );
      }
    }
  }

  /** Private method used to delete a session by its ID */
  private async deleteSessionById(
    id: string,
    deleteFromDB = true,
  ): Promise<void> {
    const session = this.sessionsById.get(id);

    if (session) {
      this.sessionsById.delete(session.id);
      this.sessionsById.delete(id);
    }

    // Delete from DB if true
    if (deleteFromDB) {
      const deleteResult =
        await DatabaseSessionInteractions.deleteSessionBySessionId(id);

      if (!deleteResult) {
        logger.error(
          "An error occurred whilst attempting to delete the session with id: " +
            id +
            " from the database.",
        );
      }
    }
  }

  /** Private method to check if a session is still valid based on TTLs
   * If not valid, deletes the session and returns false
   */
  private async checkSessionValidity(
    session: Session,
    deleteFromDB = true,
  ): Promise<boolean> {
    const now = Date.now();

    // Check for absolute TTL
    const absoluteTTL = authConfig.options.absoluteTTL;

    if (absoluteTTL) {
      const sessionAge = now - session.createdAt.getTime();
      if (sessionAge > absoluteTTL) {
        // Delete session if expired
        await this.deleteSessionById(session.id, deleteFromDB);

        return false;
      }
    }

    // Check for idle TTL
    const idleTTL = authConfig.options.idleTTL;

    if (idleTTL) {
      const lastActivity = session.getLastActivityTime();
      if (lastActivity) {
        const idleTime = now - lastActivity.getTime();
        if (idleTime > idleTTL) {
          await this.deleteSessionById(session.id, deleteFromDB);

          return false;
        }
      }
    }

    return true;
  }

  /**
   * Update activity time only if threshold has passed (avoids DB write spam)
   */
  private maybeUpdateActivity(session: Session) {
    const now = Date.now();
    const lastActivity = session.getLastActivityTime().getTime();
    const ACTIVITY_UPDATE_THRESHOLD = 60 * 1000; // 60 seconds

    if (now - lastActivity > ACTIVITY_UPDATE_THRESHOLD) {
      session.updateLastActivityTime().catch((error) => {
        logger.error(
          `Failed to update activity for session ${session.id}:`,
          error,
        );
      });
    }
  }

  // END: PRIVATE
}
