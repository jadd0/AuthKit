import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME } from "@/shared/constants";
import { GetSessionType } from "@/shared/types";

/**
 * Helper to get cookie value by name
 */
function getCookie(name: string): string | undefined {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);

  if (parts.length === 2) {
    return parts.pop()?.split(";").shift();
  }

  return undefined;
}

/** Wrapper object for client-side Session methods */
export const ClientSession = {
  /** Use this to retrieve the current auth Session for a user.
   * You may want to use this to protect a route.
   */
  async getAuth() {
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
  },

  /**
   * Delete the current session (logout)
   */
  async deleteSession(): Promise<void> {
    // Get the CSRF token from the cookie
    const csrfToken = getCookie(CSRF_COOKIE_NAME);

    if (!csrfToken) {
      throw new Error("CSRF token not found - user may not be logged in");
    }

    const res = await fetch("/api/auth/session", {
      method: "DELETE",
      headers: {
        "Content-Type": "application/json",
        [CSRF_HEADER_NAME]: csrfToken,
      },
      credentials: "include",
    });

    if (!res.ok) {
      const error = await res.json().catch(() => ({ message: res.statusText }));
      throw new Error(`Failed to delete session: ${error.message}`);
    }
  },
};
