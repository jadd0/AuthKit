"use client";

import { useState, useCallback } from "react";
import { ClientSession } from "../auth/clientSession";
import { useRouter } from "next/navigation";
import { logger } from "@/server/classes/AuthKitLogger";

interface UseLogoutResult {
  logout: () => Promise<void>;
  loading: boolean;
  error: Error | null;
}

/**
 * Hook to handle user logout
 */
export function useLogout(): UseLogoutResult {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const router = useRouter();

  const logout = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      await ClientSession.deleteSession();

      // Redirect to login page after successful logout
      router.push("/login");
    } catch (err) {
      const e = err as Error;
      setError(e);
      logger.error("Logout error:", e);
      throw e;
    } finally {
      setLoading(false);
    }
  }, [router]);

  return { logout, loading, error };
}
