import { ServerSession } from "@/server/classes/auth/server/session/serverSession";
import { routeSessionRequest } from "@/server/routes/session";
import { DataOnly } from "@/shared/utils";

/** Type of the result returned by deleting a session */
export type DeleteSessionPayload =
  | { message: "Session deleted" }
  | { message: "Invalid session" };

/** Type of the session object returned from ServerSession.getSession */
type SessionFromServer = Awaited<
  ReturnType<ServerSession["getSession"]>
>["session"];

/** Type of the result returned by getting a session */
export type GetSessionPayload =
  | { session:  DataOnly<SessionFromServer> }
  | { message: "Invalid session" };
