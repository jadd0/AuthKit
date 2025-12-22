import { serverAuth } from "@/server/core/singleton";
import { NextResponse } from "next/server";

/** Used to handle the Email-Password provider request route */
export async function routeEmailPasswordProviderRequest(
  segments: string[],
  method: string,
  body: any
) {
  // Ensure the email-password provider is configured
  if (!serverAuth.providers.emailPassword) {
    throw new Error("Email/password provider not configured");
  }

  // TODO: improve error handling and responses
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
            body.password
          );
        } catch (err) {
          return NextResponse.json(
            { message: "Invalid email or password" },
            { status: 401 }
          );
        }

        // Return response with session cookie set
        const res = NextResponse.json(
          {
            message: "Login successful",
            user: result.user,
            session: result.session,
          },
          { status: 200 }
        );

        // Set session cookie for the user
        res.headers.set("Set-Cookie", result.cookie);
        return res;
      } else {
        // Method not allowed
        return NextResponse.json(
          { message: "Method not allowed" },
          { status: 405 }
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
            body.email,
            body.password
          );
        } catch (err) {
          return NextResponse.json(
            {
              message:
                "An issue occured whilst trying to register the user. Ensure all datafields are as expected.",
            },
            { status: 401 }
          );
        }

        // Return response with session cookie set
        const res = NextResponse.json(
          {
            message: "Registration successful",
            user: result.user,
            session: result.session,
          },
          { status: 200 }
        );

        // Set session cookie for the user
        res.headers.set("Set-Cookie", result.cookie);
        return res;
      } else {
        // Method not allowed
        return NextResponse.json(
          { message: "Method not allowed" },
          { status: 405 }
        );
      }

    // END
    default:
      return NextResponse.json({ message: "Route not found" }, { status: 404 });
  }
}
