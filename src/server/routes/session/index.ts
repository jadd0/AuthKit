import { getServerSession } from "@/server/core/singleton";
import { SESSION_COOKIE_NAME } from "@/shared/constants/auth.constants";
import { verifyCsrf } from "@/shared/utils/CSRF/verifyCSRF";
import { NextRequest } from "next/server";
import { logger } from "@/server/classes/AuthKitLogger";

export async function routeSessionRequest(
  segments: string[],
  method: string,
  { body, url, request }: { body: any; url: string; request: NextRequest },
  parsedCookies: Record<string, string>,
): Promise<Response> {
  const serverSession = getServerSession();

  // Handle different session routes based on the path segments
  switch (method) {
    case "DELETE":
      // Verify CSRF token for session deletion
      const csrfVerified = verifyCsrf(request);

      if (!csrfVerified) {
        return new Response(
          JSON.stringify({ message: "CSRF validation failed" }),
          {
            status: 403,
            headers: { "Content-Type": "application/json" },
          },
        );
      }

      // Handle session deletion
      const deleteToken = parsedCookies[SESSION_COOKIE_NAME] || body.token;

      try {
        // Attempt to delete the session
        const deleteResult = await serverSession?.deleteSession(deleteToken);

        // Invalid session
        if (!deleteResult) {
          logger.error("Invalid session token for deletion:", deleteToken);

          return new Response(JSON.stringify({ message: "Invalid session" }), {
            status: 401,
            headers: { "Content-Type": "application/json" },
          });
        }
      } catch (err) {}

      return new Response(JSON.stringify({ message: "Session deleted" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });

    case "GET":
      // Handle getting session info
      const token = parsedCookies[SESSION_COOKIE_NAME] || body.token;

      // Attempt to retrieve the session
      const result = await serverSession?.getSession(token);

      // Invalid session
      if (!result) {
        logger.error("Invalid session token for retrieval: ", token);

        return new Response(JSON.stringify({ message: "Invalid session" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      }

      // Return session info
      const res = new Response(JSON.stringify({ session: result.session }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });

      res.headers.set("Set-Cookie", result.cookie);

      return res;
    default:
      return new Response(
        JSON.stringify({ message: "Session route not found" }),
        {
          status: 404,
          headers: { "Content-Type": "application/json" },
        },
      );
  }
}
