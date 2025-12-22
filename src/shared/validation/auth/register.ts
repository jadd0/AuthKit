import { accounts, users } from "@/shared/schemas";
import { createInsertSchema } from "drizzle-zod";

/** Zod schema for User registration */
export const userRegisterSchema = createInsertSchema(users);

/** Zod schema for Account registration */
export const accountRegisterSchema = createInsertSchema(accounts);
