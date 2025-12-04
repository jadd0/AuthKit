import {
  auth,
  authConfig,
  emailPasswordProvider,
} from "@/server/core/singleton";
import { DatabaseSessionInteractions } from "@/server/db/interfaces/databaseSessionInteractions";
import { NewUser } from "@/shared/schemas";
import { DEFAULT_IDLE_TTL } from "@/shared/constants";
import { userRegisterSchema } from "@/shared/validation/auth";
import { generateSessionCookie } from "@/shared/utils/session";
import { z } from "zod";

export class ServerEmailPassword {
  provider: typeof emailPasswordProvider;
  constructor() {
    this.provider = emailPasswordProvider;
  }

  /** Use this to log a user in via Email and Password */
  async login(email: string, password: string) {
    // Basic validation
    if (z.string().min(1).parse(email).length === 0) {
      throw new Error("Email is required");
    }
    if (z.string().min(1).parse(password).length === 0) {
      throw new Error("Password is required");
    }

    // Attempt to log the user in via the provider
    const user = await this.provider.login(email, password);

    // Invalid email/password combination
    if (!user) {
      throw new Error("Invalid email or password");
    }

    // Create a session for the logged-in user
    const session = await auth.sessions.createSession(user);

    // Generate session cookie
    const cookie = generateSessionCookie(
      "session",
      session.getSessionToken(),
      authConfig.options.idleTTL || DEFAULT_IDLE_TTL
    );

    return { user, session, cookie };
  }

  /** Use this to register a new user via Email and Password */
  async register(config: NewUser, password: string) {
    // Validation
    const parsedConfig = userRegisterSchema.safeParse(config);

    // Check for validation errors
    if (!parsedConfig.success) {
      const issues = parsedConfig.error.issues
        .map((i) => `- ${i.message} (at ${i.path.join(".")})`)
        .join("\n");
      throw new Error(`Invalid registration data:\n${issues}`);
    }

    // Basic password validation
    if (z.string().min(6).parse(password).length < 6) {
      throw new Error("Password must be at least 6 characters long");
    }

    // Attempt to register the user via the provider
    const user = await this.provider.register(config, password);

    if (!user) {
      throw new Error("Failed to register user");
    }

    // Create a session for the newly registered user
    const session = await auth.sessions.createSession(user);

    // Generate session cookie
    const cookie = generateSessionCookie(
      "session",
      session.getSessionToken(),
      authConfig.options.idleTTL || DEFAULT_IDLE_TTL
    );

    return { user, session, cookie };
  }
}
