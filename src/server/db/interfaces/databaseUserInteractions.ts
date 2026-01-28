import { db } from "@/server/core/singleton";
import { NewUser, users } from "@/shared/schemas";
import { eq } from "drizzle-orm";
import { User } from "@/shared/schemas";

/** A repository object to represent all user interactions in the database */
export const DatabaseUserInteractions = {
  // START: CREATE

  /** Used to create a user */
  async createUser(config: NewUser): Promise<User> {
     const user = await db.insert(users).values(config).returning();
     return user[0];
  },

  // END: CREATE

  // START: READ

  /** Used to retrieve a single user via their id */
  async getUserById(id: string): Promise<User | null> {
    const result = await db.select().from(users).where(eq(users.id, id));

    return result[0] || null;
  },

  /** Used to retrieve a user via their email */
  async getUserByEmail(email: string): Promise<User | null> {
    const result = await db.select().from(users).where(eq(users.email, email));

    return result[0] || null;
  },

  /** Used to retrieve a user via their username */
  getUserByUsername(username: string): Promise<User | null> {
    const result = db.select().from(users).where(eq(users.username, username));

    return result[0] || null;
  },

  // END: READ

  // START: UPDATE

  /** Used to update a user's email via their id */
  async updateUserEmail(email: string, id: string): Promise<User | null> {
    const result = await db
      .update(users)
      .set({ email })
      .where(eq(users.id, id))
      .returning();

    return result[0] || null;
  },

  /** Used to update a user's name via their id */
  async updateUserName(name: string, id: string): Promise<User | null> {
    const result = await db
      .update(users)
      .set({ name })
      .where(eq(users.id, id))
      .returning();

    return result[0] || null;
  },

  /** Used to update a user's username via their id */
  async updateUserUsername(username: string, id: string): Promise<User | null> {
    const result = await db
      .update(users)
      .set({ username })
      .where(eq(users.id, id))
      .returning();

    return result[0] || null;
  },

  /** Used to update a user's password via their id */
  async updateUserPassword(password: string, id: string): Promise<User | null> {
    const result = await db
      .update(users)
      .set({ password })
      .where(eq(users.id, id))
      .returning();

    return result[0] || null;
  },

  /** Used to update a user's image via their id */
  async updateUserImage(image: string, id: string): Promise<User | null> {
    const result = await db
      .update(users)
      .set({ image })
      .where(eq(users.id, id))
      .returning();

    return result[0] || null;
  },

  /** Used to update a user's roles via their id */
  async updateUserRole(roles: string[], id: string): Promise<User | null> {
    const result = await db
      .update(users)
      .set({ roles })
      .where(eq(users.id, id))
      .returning();

    return result[0] || null;
  },

  // END: UPDATE

  // START: DELETE

  /** Used to delete a user via their username*/
  async deleteUser(id: string): Promise<User | null> {
    const result = await db.delete(users).where(eq(users.id, id)).returning();

    return result[0] || null;
  },

  // END: DELETE
};
