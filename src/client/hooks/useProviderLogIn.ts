"use client";

import { useState, useCallback } from "react";

/** React hook to initiate provider sign-in process */
export function useProviderLogIn() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const logIn = useCallback(
    async (providerId: string, redirectTo?: string) => {
      setLoading(true);
      setError(null);
      try {
        const url = new URL(
          `/api/auth/provider/${providerId}/authorize`,
          window.location.origin
        );
        if (redirectTo) url.searchParams.set("redirectTo", redirectTo);
        window.location.href = url.toString();
      } catch (err) {
        setError(err as Error);
        setLoading(false);
      }
    },
    []
  );

  return { logIn, loading, error };
}
