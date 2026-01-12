import { serverSession } from "@/server/core/singleton";

export async function routeSessionRequest(
  segments: string[],
  method: string,
  { body, url }: { body: any; url: string },
  parsedCookies: Record<string, string>
): Promise<Response> {
  // Handle different session routes based on the path segments
  switch (
    method // TODO: change to segments[1] when more session routes are added
  ) {
    case "DELETE":
      // Handle session deletion
      return new Response(JSON.stringify({ message: "Session deleted" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });

    case "GET":
      // Handle getting session info
      const token = parsedCookies["session"] || body.token;

      // Attempt to retrieve the session
      const result = await serverSession.getSession(token);

      // Invalid session
      if (!result) {
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
        }
      );
  }
}
