import { useState, useEffect, use } from "react";
import { ClientSession } from "../auth/clientSession";
import { SessionWithUser } from "@/shared/types";

/** React hook to manage and provide authentication state */
export function useAuth() {
  const [session, setSession] = useState<SessionWithUser | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchAuth() {
      try {
        const authSession = await ClientSession.getAuth();
        setSession(authSession);
        setLoading(false);
      } catch (error) {
        console.error("Error fetching auth session:", error);
        setLoading(false);
      }
    }

    fetchAuth();
  }, []);

  return { session, loading };
}
