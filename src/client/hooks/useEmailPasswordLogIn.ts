"use client";

import { useState, useCallback } from "react";
import { ClientEmailPassword } from "../auth/providers/clientEmailPassword";

interface UseEmailPasswordLogInResult {
  login: (email: string, password: string) => Promise<void>;
  loading: boolean;
  error: Error | null;
}

/** React hook to initiate email/password login process */
export function useEmailPasswordLogin(): UseEmailPasswordLogInResult {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const login = useCallback(async (email: string, password: string) => {
    setLoading(true);
    setError(null);
    
    try {
      await ClientEmailPassword.login(email, password);
    } catch (err) {
      setError(err as Error);
    } finally {
      setLoading(false);
    }
  }, []);

  return { login, loading, error };
}
