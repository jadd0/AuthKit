import { AccountRateLimiter } from "@/server/classes/auth/accountRateLimiter";
import { authConfig, logger, serverAuth } from "@/server/core/singleton";
import { secureResponse } from "@/shared/utils/addSecurityHeaders";
import { NextRequest } from "next/server";

// Rate limiter instances (initialised lazily)
let loginRateLimiter: AccountRateLimiter | undefined = undefined;
let registrationRateLimiter: AccountRateLimiter | undefined = undefined;
let rateLimitersInitialized = false;

/**
 * Initialise rate limiters lazily (only once, when first request comes in)
 */
function ensureRateLimitersInitialised() {
  if (rateLimitersInitialized) return;

  const credentialsOptions = authConfig?.providers.find(
    (p) => p.type === "credentials",
  );

  if (credentialsOptions?.rateLimiting) {
    const rateLimitingConfig = credentialsOptions.rateLimiting;

    loginRateLimiter = new AccountRateLimiter({
      windowMs: rateLimitingConfig.rateLimitTime,
      maxAttempts: rateLimitingConfig.rateLimitMaxAttempts,
      lockoutMs: rateLimitingConfig.rateLimitLockoutTime,
      skipSuccessfulRequests: rateLimitingConfig.rateLimitSkipSuccessful,
    });

    registrationRateLimiter = new AccountRateLimiter({
      windowMs: rateLimitingConfig.rateLimitTime,
      maxAttempts: Math.min(3, rateLimitingConfig.rateLimitMaxAttempts),
      lockoutMs: rateLimitingConfig.rateLimitLockoutTime,
      skipSuccessfulRequests: true,
    });
  }

  rateLimitersInitialized = true;
}

/** Used to handle the Email-Password provider request route */
export async function routeEmailPasswordProviderRequest(
  segments: string[],
  method: string,
  { body, url, request }: { body: any; url: string; request: NextRequest },
) {
  // Initialise rate limiters on first request
  ensureRateLimitersInitialised();

  // Ensure the email-password provider is configured
  if (!serverAuth.providers.emailPassword) {
    throw new Error("Email/password provider not configured");
  }

  // Handle email-password provider routes
  switch (segments[2]) {
    // START: LOGIN
    case "login":
      if (method === "POST") {
        // Check rate limiter
        if (loginRateLimiter) {
          const rateCheck = loginRateLimiter.checkRateLimit(body.email);

          if (!rateCheck.allowed) {
            return secureResponse(
              {
                message: rateCheck.message,
                lockedUntil: rateCheck.lockedUntil,
              },
              { status: 429 },
            );
          }
        }

        // Call the server auth email-password login method
        let result;
        try {
          result = await serverAuth.providers.emailPassword.login(
            body.email,
            body.password,
          );

          // SUCCESS - reset rate limit
          if (loginRateLimiter) {
            loginRateLimiter.recordAttempt(body.email, true);
          }

          return secureResponse(
            {
              message: "Login successful",
              user: result.user,
              session: result.session,
            },
            { status: 200, headers: result.headers },
          );
        } catch (err: any) {
          // Handle invalid credentials
          if (err.message === "Invalid email or password") {
            // FAILURE - record failed attempt
            if (loginRateLimiter) {
              const recordResult = loginRateLimiter.recordAttempt(
                body.email,
                false,
              );

              // Account now locked
              if (!recordResult.allowed) {
                return secureResponse(
                  {
                    message: recordResult.message,
                    lockedUntil: recordResult.lockedUntil,
                  },
                  { status: 429 },
                );
              }

              return secureResponse(
                {
                  message: "Invalid email or password",
                  remainingAttempts: recordResult.remainingAttempts,
                },
                { status: 401 },
              );
            }

            return secureResponse(
              { message: "Invalid email or password" },
              { status: 401 },
            );
          }

          // Handle validation errors
          if (
            err.message === "Email is required" ||
            err.message === "Password is required"
          ) {
            return secureResponse({ message: err.message }, { status: 400 });
          }

          // Generic server error
          logger.error("Login error: ", err);

          return secureResponse(
            { message: "Internal server error" },
            { status: 500 },
          );
        }
      } else {
        return secureResponse(
          { message: "Method not allowed" },
          { status: 405 },
        );
      }
    // END: LOGIN

    // START: REGISTER
    case "register":
      if (method === "POST") {
        // Check if rate limiting is applicable
        if (registrationRateLimiter) {
          const rateCheck = registrationRateLimiter.checkRateLimit(
            body.userConfig.email,
          );

          if (!rateCheck.allowed) {
            return secureResponse(
              {
                message: rateCheck.message,
                lockedUntil: rateCheck.lockedUntil,
              },
              { status: 429 },
            );
          }
        }

        let result;
        try {
          result = await serverAuth.providers.emailPassword.register(
            { email: body.userConfig.email, name: body.userConfig.name },
            body.password,
          );

          // SUCCESS - reset rate limit
          if (registrationRateLimiter) {
            registrationRateLimiter.recordAttempt(body.userConfig.email, true);
          }

          return secureResponse(
            {
              message: "Registration successful",
              user: result.user,
              session: result.session,
            },
            { status: 201, headers: result.headers }, // 201 Created
          );
        } catch (err) {
          logger.error("Registration error:", err);

          // FAILURE - record attempt
          if (registrationRateLimiter) {
            const recordResult = registrationRateLimiter.recordAttempt(
              body.userConfig.email,
              false,
            );

            if (!recordResult.allowed) {
              return secureResponse(
                {
                  message: recordResult.message,
                  lockedUntil: recordResult.lockedUntil,
                },
                { status: 429 },
              );
            }
          }

          return secureResponse(
            {
              message:
                "Registration failed. Please check your details and try again.",
            },
            { status: 400 },
          );
        }
      } else {
        return secureResponse(
          { message: "Method not allowed" },
          { status: 405 },
        );
      }
    // END: REGISTER

    default:
      return secureResponse({ message: "Route not found" }, { status: 404 });
  }
}
