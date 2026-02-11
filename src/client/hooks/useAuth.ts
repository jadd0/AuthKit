import { useState, useEffect } from "react";
import { ClientSession } from "../auth/clientSession";
import { SessionWithUser } from "@/shared/types";
import { logger } from "@/server/classes/AuthKitLogger";

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
        logger.error("Error fetching authentication session", error);
        setLoading(false);
      }
    }

    fetchAuth();
  }, []);

  return { session, loading };
}
