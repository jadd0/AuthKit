import { db } from "@/server/core/singleton";
import { NewSession, Session, sessions } from "@/shared/schemas";
import { eq, lt, sql } from "drizzle-orm";

/** A repository object to represent all user authentication sessions interactions in the database */
export const DatabaseSessionInteractions = {
  // START: CREATE

  /** Used to create a user session for authentication */
  async createSession(config: NewSession): Promise<Session> {
    const result = await db.insert(sessions).values(config).returning();

    return result[0];
  },

  // END: CREATE

  // START: READ

  /** Used to retrieve a session by via session ID */
  async getSessionById(id: string): Promise<Session | null> {
    const result = await db.select().from(sessions).where(eq(sessions.id, id));

    return result[0] || null;
  },

  /** Used to retrieve the session related to a specific user via their user ID */
  async getSessionsByUserId(userId: string): Promise<Session | null> {
    const result = await db
      .select()
      .from(sessions)
      .where(eq(sessions.userId, userId));

    return result[0] || null;
  },

  /** Used to retrieve all active sessions */
  async getAllSessions() {
    return await db.select().from(sessions);
  },

  // END: READ

  // START: UPDATE
  // TODO: make these into a transaction?

  /** Used to update a session's token by user ID */
  async updateSessionTokenByUserId(
    token: string,
    userId: string
  ): Promise<Session | null> {
    const result = await db
      .update(sessions)
      .set({ sessionToken: token })
      .where(eq(sessions.userId, userId))
      .returning();

    return result[0] || null;
  },

  /** Used to update a session's token by session ID */
  async updateSessionTokenById(
    token: string,
    id: string
  ): Promise<Session | null> {
    const result = await db
      .update(sessions)
      .set({ sessionToken: token })
      .where(eq(sessions.id, id))
      .returning();

    return result[0] || null;
  },

  /** Used to update and mark down when the user last interacted with the session via Session ID. Used to track idle TTL (sliding). Passes timestamp in so server in sync with DB */
  async updateLastActivityTimeById(
    id: string,
    timestamp: Date
  ): Promise<Session> {
    const result = await db
      .update(sessions)
      .set({ lastActivityAt: timestamp })
      .where(eq(sessions.id, id))
      .returning();

    return result[0] || null;
  },

  /** Used to update and mark down when the user last interacted with the session via User ID. Used to track idle TTL (sliding). Passes timestamp in so server in sync with DB */
  async updateLastActivityTimeByUserId(
    userId: string,
    timestamp: Date
  ): Promise<Session> {
    const result = await db
      .update(sessions)
      .set({ lastActivityAt: timestamp })
      .where(eq(sessions.userId, userId))
      .returning();

    return result[0] || null;
  },

  // END: UPDATE

  // START: DELETE

  /** Used to delete a user's authentication session by user's ID */
  async deleteSessionByUserId(userId: string): Promise<Session | null> {
    const result = await db
      .delete(sessions)
      .where(eq(sessions.userId, userId))
      .returning();

    return result[0] || null;
  },

  /** Used to delete a user's authentication session by session ID */
  async deleteSessionBySessionId(id: string): Promise<Session | null> {
    const result = await db
      .delete(sessions)
      .where(eq(sessions.id, id))
      .returning();

    return result[0] || null;
  },

  // TODO: implement properly
  /** Used to delete expired sessions from the database, returns number of deleted rows */
  async deleteExpiredSessions(): Promise<number> {
    // const result = await db
    //   .delete(sessions)
    //   .where(lt(sessions.expires, sql`now()`))
    //   .run();

    // return result.changes;
    return 0;
  },
  // END: DELETE
};
