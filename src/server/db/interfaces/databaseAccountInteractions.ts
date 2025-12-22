import { db } from "@/server/core/singleton";
import { Account, accounts, NewAccount } from "@/shared/schemas";
import { Providers } from "@/shared/types";
import { and, eq } from "drizzle-orm";

/** A repository object to represent all account connections interactions in the database */
export const DatabaseAccountInteractions = {
  // START: CREATE

  /** Used to create an account connection (eg: a provider) */
  async createAccount(config: NewAccount): Promise<Account[]> {
    return db.insert(accounts).values(config).returning();
  },

  // END: CREATE

  // START: READ

  /** Used to retrive user account connections via the user's ID */
  async getAccountsByUserId(id: string): Promise<Account[] | null> {
    return await db.select().from(accounts).where(eq(accounts.userId, id));
  },

  /** Used to retrieve a unique account connection via composite key (userId + provider) */
  async getAccountByCompositeKey(
    userId: string,
    provider: Providers
  ): Promise<Account | null> {
    const result = await db
      .select()
      .from(accounts)
      .where(and(eq(accounts.userId, userId), eq(accounts.provider, provider)));

    return result[0] || null;
  },

  /** Used to retrieve a unique account connection via provider account ID */
  async getAccountByProviderAccountId(
    accountId: string
  ): Promise<Account | null> {
    const result = await db
      .select()
      .from(accounts)
      .where(eq(accounts.providerAccountId, accountId));

    return result[0] || null;
  },

  // END: READ

  // START: UPDATE

  /** Used to update a user's password (if via email/password provider) via the composite key (userId + provider) */
  async updateAccountPassword(
    password: string,
    userId: string
  ): Promise<Account | null> {
    const result = await db
      .update(accounts)
      .set({ password })
      .where(eq(accounts.userId, userId))
      .returning();

    return result[0] || null;
  },

  /** Used to update a user's password hash (if via email/password provider) via the composite key (userId + provider) */
  async updateAccountPasswordHash(
    passwordHash: string,
    userId: string
  ): Promise<Account | null> {
    const result = await db
      .update(accounts)
      .set({ passwordHash })
      .where(eq(accounts.userId, userId))
      .returning();

    return result[0] || null;
  },

  // END: UPDATE

  // START: DELETE

  /** Used to delete an account provider via the composite key (userId + provider) */
  async deleteAccount(
    userId: string,
    provider: Providers
  ): Promise<Error | Account | null> {
    // Check if only account connection for user
    const connections = await this.getAccountsByUserId(userId);

    // If only one connection, prevent deletion
    if (connections && connections.length <= 1) {
      return new Error("Cannot delete the only account connection for a user.");
    }

    const result = await db
      .delete(accounts)
      .where(and(eq(accounts.userId, userId), eq(accounts.provider, provider)))
      .returning();
    return result[0] || null;
  },

  // END: DELETE
};
