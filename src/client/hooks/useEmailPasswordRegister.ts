"use client";

import { NewUserClient } from "@/shared/schemas";
import { useCallback, useState } from "react";
import { ClientEmailPassword } from "../auth/providers/clientEmailPassword";

interface UseEmailPasswordRegisterResult {
  register: (userConfig: NewUserClient, password: string) => Promise<any>;
  loading: boolean;
  error: Error | null;
}

/** Hook to register a user with email-password provider */
export function useEmailPasswordRegister(): UseEmailPasswordRegisterResult {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  /** Callable register function */
  const register = useCallback(
    async (userConfig: NewUserClient, password: string) => {
      setLoading(true);
      setError(null);

      try {
        const result = await ClientEmailPassword.register(userConfig, password);

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
    },
    [],
  );

  return { register, loading, error };
}
