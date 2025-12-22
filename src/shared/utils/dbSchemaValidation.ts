import { db } from "@/server/core/singleton";
import {
  users,
  NewUser,
  accounts,
  NewAccount,
  sessions,
  NewSession,
} from "@/shared/schemas";
import { eq } from "drizzle-orm";

/** Helper function to test transaction insertion. Runs a function in a transaction and always rolls back, so no data is persisted */
async function testInTransaction(fn: () => Promise<void>) {
  await db.transaction(async (trx: any) => {
    try {
      await fn();
      // Throw after insert to always force rollback
      throw new Error("Rollback transaction after schema test.");
    } catch (err: any) {
      // Only swallow the rollback error, not real errors
      if (err.message !== "Rollback transaction after schema test.") {
        throw err;
      }
    }
  });
}

/** Tester function used on runtime start to ensure the given database matches the necessary schema */
export async function dbSchemaValidation(): Promise<boolean> {
  try {
    // To avoid FK issues, insert user first and reuse "fake-user-id"
    await testInTransaction(async () => {
      await db.insert(users).values({
        id: "fake-user-id",
        name: "seed",
        email: "seed@seed.com",
        emailVerified: new Date(),
        image: "example.com",
        username: "seed",
      } satisfies NewUser);
      // Now run insert tests using the same userId
      await db.insert(accounts).values({
        userId: "fake-user-id",
        type: "test",
        provider: "test-provider",
        createdAt: new Date(),
        updatedAt: new Date(),
      } satisfies NewAccount);
      await db.insert(sessions).values({
        id: "fake-session-id",
        sessionToken: "test-session-token",
        userId: "fake-user-id",
        createdAt: new Date(),
        lastActivityAt: new Date()
      } satisfies NewSession);
      // Force rollback
      throw new Error("Rollback transaction after schema test.");
    });

    /** Fallback deletions of test data incase transaction rollback does not work */
    await db.delete(accounts).where(eq(accounts.userId, "fake-user-id"));
    await db.delete(sessions).where(eq(sessions.id, "fake-session-id"));
    await db.delete(users).where(eq(users.id, "fake-user-id"));

    return true;
  } catch (e: any) {
    throw new Error(
      "Database schema validation failed. Ensure all migrations are complete. Check the README.md for migration instructions.\n\nDetails: " +
        e
    );
  }
}
