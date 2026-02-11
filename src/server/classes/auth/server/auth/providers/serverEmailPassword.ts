import {
  auth,
  authConfig,
  emailPasswordProvider,
} from "@/server/core/singleton";
import { DatabaseSessionInteractions } from "@/server/db/interfaces/databaseSessionInteractions";
import { NewUser } from "@/shared/schemas";
import {
  CSRF_COOKIE_NAME,
  DEFAULT_IDLE_TTL,
  SESSION_COOKIE_NAME,
} from "@/shared/constants";
import { userRegisterSchema } from "@/shared/validation/auth";
import {
  generateSessionCookie,
  generateSessionToken,
} from "@/shared/utils/session";
import { z } from "zod";
import z4 from "zod/v4";
import { generateCSRFCookie } from "@/shared/utils/CSRF/generateCSRFCookie";
import { generateCsrfToken } from "@/shared/utils";

export class ServerEmailPassword {
  provider: typeof emailPasswordProvider;
  constructor() {
    this.provider = emailPasswordProvider;

    // Ensure saltingRounds has a default value if not provided
    if (
      authConfig.providers.find((p) => p.type === "credentials")!
        .saltingRounds == undefined
    ) {
      authConfig.providers.find(
        (p) => p.type === "credentials",
      )!.saltingRounds = 10;
    }
  }

  /** Use this to log a user in via Email and Password */
  async login(email: string, password: string) {
    // Basic validation
    if (!email || z.string().min(1).parse(email).length === 0) {
      throw new Error("Email is required");
    }
    if (!password || z.string().min(1).parse(password).length === 0) {
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

    // Failed to create session for user
    if (!session) {
      throw new Error("Failed to create session for user");
    }

    // Generate session cookie
    const sessionCookie = generateSessionCookie(
      SESSION_COOKIE_NAME,
      session.getSessionToken(),
      authConfig.options.idleTTL || DEFAULT_IDLE_TTL,
    );

    // Generate CSRF token and cookie for secure token validation
    const CSRFToken = generateCsrfToken(session.getSessionToken());
    const CSRFCookie = generateCSRFCookie(CSRFToken);

    // Append cookies to response header
    const headers = new Headers();

    headers.append("Set-Cookie", sessionCookie);
    headers.append("Set-Cookie", CSRFCookie);

    return { user, session, headers };
  }

  /** Use this to register a new user via Email and Password */
  async register(config: NewUser, password: string) {
    // Validation
    const parsedConfig = userRegisterSchema.safeParse(config);

    // Check for validation errors
    if (!parsedConfig.success) {
      throw new Error(
        `Invalid registration data:\n${z.prettifyError(parsedConfig.error)}`,
      );
    }

    // TODO: decide on and implement additional password validation rules (e.g. complexity requirements)
    // // Basic password validation
    // if (z.string().min(6).parse(password).length < 6) {
    //   throw new Error("Password must be at least 6 characters long");
    // }

    // Attempt to register the user via the provider
    const user = await this.provider.register(config, password);

    if (!user) {
      throw new Error("Failed to register user");
    }

    // Create a session for the newly registered user
    const session = await auth.sessions.createSession(user);

    // Generate session cookie
    const sessionCookie = generateSessionCookie(
      SESSION_COOKIE_NAME,
      session.getSessionToken(),
      authConfig.options.idleTTL || DEFAULT_IDLE_TTL,
    );

    // Generate CSRF token and cookie for secure token validation
    const CSRFToken = generateCsrfToken(session.getSessionToken());
    const CSRFCookie = generateCSRFCookie(CSRFToken);

    // Append cookies to response header
    const headers = new Headers();

    headers.append("Set-Cookie", sessionCookie);
    headers.append("Set-Cookie", CSRFCookie);

    return { user, session, headers };
  }
}
