"use client";

import { User } from "@/shared/schemas";
import { useAuth } from "./useAuth";
import { useRouter } from "next/navigation";
import { useEffect, useMemo } from "react";

interface AuthGuardOptions {
  redirectTo?: string; // A path for the situation of an unsuccessful access attempt. Eg: "/login"
  onUnauthorised?: () => void; // Optional callback function for unauthorised login attempt
  mode?: "any" | "all"; // Used to define what union of required roles is necessary. any = partial subset of required roles, all = equivalence of the required roles
}

/**
 * React hook that protects a page/component based on the current user's roles.
 *
 * @param requiredRoles Array of roles that are allowed to access the page. If empty, any authenticated user can access.
 * @param options Configuration options controlling redirects, callbacks, and how roles are checked.
 * @param options.redirectTo Optional path or URL to navigate to when access is denied (for example, "/login").
 * @param options.onUnauthorised Optional callback invoked when the user is not authorised to access the page.
 * @param options.mode Determines how required roles are checked: "any" (at least one role required) or "all" (every role required). Defaults to "any".
 */

export function useAuthGuard(
  requiredRoles: string[] = [],
  options: AuthGuardOptions
) {
  const { redirectTo, onUnauthorised, mode = "any" } = options;
  const { session, loading } = useAuth();
  const router = useRouter(); // Next.js Router wrapper

  // Check the user has a certain role
  const hasRoles = useMemo(() => {
    if (!session?.user || !requiredRoles.length) return false;

    // Check if the user has any role required
    if (mode == "any") {
      return requiredRoles.some((role: string) =>
        session.user.roles.includes(role)
      );
    }

    // Check the user has every role required
    return requiredRoles.every((role) => session.user.roles.includes(role));
  }, [session, requiredRoles, mode]);

  const isAuthenticated = session?.user;
  const hasAccess = isAuthenticated && (requiredRoles.length ? hasRoles : true);

  useEffect(() => {
    if (loading) return;

    if (!hasAccess) {
      if (onUnauthorised) {
        try {
          onUnauthorised();
        } catch (error: any) {
          console.error(
            "There was an error whilst trying to use the callback function given for useAuthGuard."
          );
        }
      }

      try {
        if (redirectTo) {
          router.replace(redirectTo);
        }
      } catch (error: any) {
        console.error(
          "There was an issue whilst trying to redirect to the given redirect path/URL for useAuthGuard."
        );
      }
    }
  }, [hasAccess, loading, redirectTo, onUnauthorised, router]);

  return {
    session,
    loading,
    hasAccess,
    hasRole: (role: string) => !!session?.user?.roles.includes(role),
    hasAnyRole: (roles: string[]) =>
      !!session?.user && roles.some((r) => !!session?.user?.roles.includes(r)),
    hasAllRoles: (roles: string[]) =>
      !!session?.user && roles.every((r) => !!session?.user?.roles.includes(r)),
  };
}
