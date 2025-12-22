import { serverSession } from "@/server/core/singleton";
import { Session, User } from "@/shared/schemas";
import { Session as SessionClass } from "@/server/classes/auth/session";

type ClassProps<C> = {
  [K in keyof C as C[K] extends Function ? never : K]: C[K];
};

/** Type representing a Session with union of the referenced User */
export type SessionWithUser = ClassProps<SessionClass>;

/** Type representing the session returned by getSession */
export type GetSessionType = Awaited<
  ReturnType<typeof serverSession.getSession>
>;
