import { pgTable, timestamp, varchar } from "drizzle-orm/pg-core";

export const users = pgTable("users", {
  /** The primary key for the user table; A unique reference to each user */
  id: varchar("id")
    .primaryKey()
    .$defaultFn(() => crypto.randomUUID()),

  /** The username for the user, unique to each user, although the user need not have a username */
  username: varchar("username").unique(),

  /** The full name of the user, usually retrieved from OIDC */
  name: varchar("name").notNull(),

  /** The email of the user, unique to each user */
  email: varchar("email").notNull().unique(),

  /** Whether the user's email has been verified, and when it has been verified */
  emailVerified: timestamp("emailVerified"),

  /** Profile picture for the user, a URL pointint to an image stored elsewhere */
  image: varchar("image"),

  /** A timestamp explaining when the user was created */
  createdAt: timestamp("createdAt").defaultNow().notNull(),

  /** A timestamp explaining when the user was last updated */
  updatedAt: timestamp("updatedAt").defaultNow().notNull(), // TODO: add trigger to update on row update
});

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;