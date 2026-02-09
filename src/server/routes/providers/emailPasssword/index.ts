import { serverAuth } from "@/server/core/singleton";
import { secureResponse } from "@/shared/utils/addSecurityHeaders";
import { NextResponse } from "next/server";

/** Used to handle the Email-Password provider request route */
export async function routeEmailPasswordProviderRequest(
  segments: string[],
  method: string,
  { body, url, request }: { body: any; url: string; request: Request },
) {
  // Ensure the email-password provider is configured
  if (!serverAuth.providers.emailPassword) {
    throw new Error("Email/password provider not configured");
  }

  // Handle email-password provider routes
  switch (segments[2]) {
    // START: LOGIN

    // Handle login route
    case "login":
      if (method === "POST") {
        // Call the server auth email-password login method
        let result;
        try {
          result = await serverAuth.providers.emailPassword.login(
            body.email,
            body.password,
          );
        } catch (err: any) {
          if (err.message === "Invalid email or password") {
            return secureResponse(
              { message: "Invalid email or password" },
              { status: 401 },
            );
          }

          if (
            err.message === "Email is required" ||
            err.message === "Password is required"
          ) {
            return secureResponse({ message: err.message }, { status: 400 });
          }

          console.error("Login error:", err);

          return secureResponse({ message: err }, { status: 500 });
        }

        // Return response with session cookie set
        const res = NextResponse.json(
          {
            message: "Login successful",
            user: result.user,
            session: result.session,
          },
          { status: 200, headers: result.headers },
        );

        return res;
      } else {
        // Method not allowed
        return secureResponse(
          { message: "Method not allowed" },
          { status: 405 },
        );
      }

    // END

    // START: REGISTER

    // Handle register route
    case "register":
      if (method === "POST") {
        // Call the server auth email-password register method
        let result;

        try {
          result = await serverAuth.providers.emailPassword.register(
            { email: body.userConfig.email, name: body.userConfig.name },
            body.password,
          );
        } catch (err) {
          console.error("Registration error:", err);

          return secureResponse(
            {
              message:
                "An issue occured whilst trying to register the user. Ensure all datafields are as expected.",
            },
            { status: 401 },
          );
        }

        // Return response with session cookie set
        const res = secureResponse(
          {
            message: "Registration successful",
            user: result.user,
            session: result.session,
          },
          { status: 200, headers: result.headers },
        );

        return res;
      } else {
        // Method not allowed
        return secureResponse(
          { message: "Method not allowed" },
          { status: 405 },
        );
      }

    // END
    default:
      return secureResponse({ message: "Route not found" }, { status: 404 });
  }
}
