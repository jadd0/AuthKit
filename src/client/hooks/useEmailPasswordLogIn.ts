"use client";

import { useState, useCallback } from "react";
import { ClientEmailPassword } from "../auth/providers/clientEmailPassword";

interface UseEmailPasswordLogInResult {
  login: (email: string, password: string) => Promise<any>;
  loading: boolean;
  error: Error | null;
}

/** React hook to initiate email/password login process */
export function useEmailPasswordLogin(): UseEmailPasswordLogInResult {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  /** Callable login function */
  const login = useCallback(async (email: string, password: string) => {
    setLoading(true);
    setError(null);

    try {
      const result = await ClientEmailPassword.login(email, password);

      // Set the session cookie
      document.cookie = result.cookie;

      return { user: result.user, session: result.session };
    } catch (err) {
      const e = err as Error;
      setError(err as Error);
      throw e;
    } finally {
      setLoading(false);
    }
  }, []);

  return { login, loading, error };
}
