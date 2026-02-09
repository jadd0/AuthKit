import { serverSession } from "@/server/core/singleton";
import { SESSION_COOKIE_NAME } from "@/shared/constants/auth.constants";
import { verifyCsrf } from "@/shared/utils/CSRF/verifyCSRF";
import { NextRequest } from "next/server";

export async function routeSessionRequest(
  segments: string[],
  method: string,
  { body, url, request }: { body: any; url: string; request: NextRequest },
  parsedCookies: Record<string, string>,
): Promise<Response> {
  // Handle different session routes based on the path segments
  switch (
    method // TODO: change to segments[1] when more session routes are added
  ) {
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

      // Attempt to delete the session
      const deleteResult = await serverSession.deleteSession(deleteToken);

      // Invalid session
      if (!deleteResult) {
        console.error("Invalid session token for deletion:", deleteToken);

        return new Response(JSON.stringify({ message: "Invalid session" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      }

      return new Response(JSON.stringify({ message: "Session deleted" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });

    case "GET":
      // Handle getting session info
      const token = parsedCookies[SESSION_COOKIE_NAME] || body.token;

      // Attempt to retrieve the session
      const result = await serverSession.getSession(token);

      // Invalid session
      if (!result) {
        console.error("Invalid session token for retrieval: ", token);

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
