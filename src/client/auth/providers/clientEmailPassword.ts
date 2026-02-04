import { NewUserClient } from "@/shared/schemas/users.schemas";

/** Object of methods for client-side email-password provider */
export const ClientEmailPassword = {
  /** Use this to log a user in via Email and Password */
  async login(email: string, password: string) {
    // No email or password provided
    if (!email || !password) {
      throw new Error("Email and password must be provided");
    }

    // Ensure this is being run on the client side
    // TODO: better way to check for client side ? and maybe check for all client-side features in general?
    if (typeof window === "undefined") {
      throw new Error(
        "ClientEmailPassword can only be used on the client side",
      );
    }

    // Request to backend to log the user in via the backend auth class (more secure)
    const res = await fetch("/api/auth/provider/emailPassword/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ email, password }),
    });

    // Login failed
    if (!res.ok) {
      throw new Error(`Login failed: ${res.statusText}`);
    }

    // Login successful, retrieve data
    const data = await res.json();

    // TODO: append to client-side session store and context

    return data;
  },

  /** Use this to register a user with email and password */
  async register(userConfig: NewUserClient, password: string) {
    // Ensure this is being run on the client side
    if (typeof window === "undefined") {
      throw new Error(
        "ClientEmailPassword can only be used on the client side",
      );
    }

    // Request to backend to register the user via the backend auth class (more secure)
    const res = await fetch("/api/auth/provider/emailPassword/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ userConfig, password }),
    });

    // Registration failed
    if (!res.ok) {
      throw new Error(`Registration failed: ${res.statusText}`);
    }

    // Registration successful, retrieve data
    const data = await res.json();

    // TODO: append to client-side session store and context

    return data;
  },
};
