import { getDb } from "@/server/core/singleton";
import { NewSession, Session, sessions } from "@/shared/schemas";
import { and, eq, lt, or, sql } from "drizzle-orm";

/** A repository object to represent all user authentication sessions interactions in the database */
export const DatabaseSessionInteractions = {
  // START: CREATE

  /** Used to create a user session for authentication */
  async createSession(config: NewSession): Promise<Session> {
    const db = getDb();
    if (!db) throw new Error("Database not initialized");

    const result = await db.insert(sessions).values(config).returning();

    return result[0];
  },

  // END: CREATE

  // START: READ

  /** Used to retrieve a session by via session ID */
  async getSessionById(id: string): Promise<Session | null> {
    const db = getDb();
    if (!db) throw new Error("Database not initialized");

    const result = await db.select().from(sessions).where(eq(sessions.id, id));

    return result[0] || null;
  },

  /** Used to retrieve the session related to a specific user via their user ID */
  async getSessionsByUserId(userId: string): Promise<Session | null> {
    const db = getDb();
    if (!db) throw new Error("Database not initialized");

    const result = await db
      .select()
      .from(sessions)
      .where(eq(sessions.userId, userId));

    return result[0] || null;
  },

  /** Used to retrieve all active sessions */
  async getAllSessions() {
    const db = getDb();
    if (!db) throw new Error("Database not initialized");

    return await db.select().from(sessions);
  },

  // END: READ

  // START: UPDATE

  /**
   * Used to rotate a session token by session ID
   */
  async rotateSessionToken(
    id: string,
    newToken: string,
  ): Promise<Session | null> {
    const db = getDb();
    if (!db) throw new Error("Database not initialized");

    const result = await db
      .update(sessions)
      .set({ sessionToken: newToken })
      .where(eq(sessions.id, id))
      .returning();

    return result[0] ?? null;
  },

  /** Used to update a session's token by user ID */
  async updateSessionTokenByUserId(
    token: string,
    userId: string,
  ): Promise<Session | null> {
    const db = getDb();
    if (!db) throw new Error("Database not initialized");

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
    id: string,
  ): Promise<Session | null> {
    const db = getDb();
    if (!db) throw new Error("Database not initialized");

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
    timestamp: Date,
  ): Promise<Session> {
    const db = getDb();
    if (!db) throw new Error("Database not initialized");

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
    timestamp: Date,
  ): Promise<Session> {
    const db = getDb();
    if (!db) throw new Error("Database not initialized");

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
    const db = getDb();
    if (!db) throw new Error("Database not initialized");

    const result = await db
      .delete(sessions)
      .where(eq(sessions.userId, userId))
      .returning();

    return result[0] || null;
  },

  /** Used to delete a user's authentication session by session ID */
  async deleteSessionBySessionId(id: string): Promise<Session | null> {
    const db = getDb();
    if (!db) throw new Error("Database not initialized");

    const result = await db
      .delete(sessions)
      .where(eq(sessions.id, id))
      .returning();

    return result[0] || null;
  },

  /** Used to delete expired sessions from the database, returns number of deleted rows */
  async deleteExpiredSessions(
    absoluteTTL?: number,
    idleTTL?: number,
  ): Promise<number> {
    const db = getDb();
    if (!db) throw new Error("Database not initialized");

    const conditions = [];

    // Delete sessions older than absoluteTTL
    if (absoluteTTL) {
      const absoluteExpiry = new Date(Date.now() - absoluteTTL);
      conditions.push(lt(sessions.createdAt, absoluteExpiry));
    }

    // Delete sessions with idle time exceeding idleTTL
    if (idleTTL) {
      const idleExpiry = new Date(Date.now() - idleTTL);
      conditions.push(
        and(
          sql`${sessions.lastActivityAt} IS NOT NULL`,
          lt(sessions.lastActivityAt, idleExpiry),
        ),
      );
    }

    if (conditions.length === 0) return 0;

    const result = await db
      .delete(sessions)
      .where(or(...conditions))
      .returning();

    return result.length;
  },

  // END: DELETE
};
