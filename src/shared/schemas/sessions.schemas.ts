import { pgTable, timestamp, varchar } from "drizzle-orm/pg-core";
import { users } from "./users.schemas";

export const sessions = pgTable("sessions", {
  /** The primary key for the session table; A unique reference to each session */
  id: varchar("id")
    .primaryKey()
    .$defaultFn(() => crypto.randomUUID()),

  /** The session token used to validate the session */
  sessionToken: varchar("sessionToken").notNull().unique(),

  /** The user ID related to the session */
  userId: varchar("userId")
    .notNull()
    .references(() => users.id),

  /** A timestamp explaining when the last user activity was (used for idle TTL) */
  lastActivityAt: timestamp("lastActivityAt").defaultNow(),

  /** A timestamp explaining when the session was created (used for absolute TTL) */
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type Session = typeof sessions.$inferSelect;
export type NewSession = typeof sessions.$inferInsert;
