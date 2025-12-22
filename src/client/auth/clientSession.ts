import { GetSessionType } from "@/shared/types";

/** Wrapper object for client-side Session methods */
export const ClientSession = {
  /** Use this to retrieve the current auth Session for a user.
   * You may want to use this to protect a route.
   */
  async getAuth() {
    console.log("hello from client session");
    // TODO: find a better way to handle this as cannot import authConfig directly due to server/client separation
    // if (!auth) {
    //   throw new Error("Auth module is not initialised");
    // }

    const res = await fetch("/api/auth/session", {
      method: "GET",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
    });

    // Failed to retrieve session
    if (!res.ok) {
      throw new Error(`Failed to retrieve session: ${res.statusText}`);
    }

    const data: GetSessionType = await res.json();
    return data.session;
  }
}
