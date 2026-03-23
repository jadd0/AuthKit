# AuthKit - Next.js App Router Authentication

AuthKit is a modular authentication library for the Next.js App Router. It combines credential‑based and OAuth 2.1/OIDC flows with server‑side sessions, middleware‑based route protection, and a strongly typed developer experience.

This README explains how to initialise AuthKit in a new Next.js App Router project and how to apply the bundled database migrations.

## 1) PROJECT INITIALISATION:

Create a Next.js App Router project in the usual way:

Create a Next.js app normally with:

```console
npx create-next-app@latest
```

Install AuthKit and its peer dependencies (Drizzle, PostgreSQL driver, etc.) according to the package instructions.

## 2) Environment Configuration:

AuthKit requires a PostgreSQL database. You can configure the connection either via a single database URL or via a connection pool configuration.

Create or update your .env file with one of the following:

### Option 1) **Database URL (RECOMMENDED):**

```env
DATABASE_URL: your_database_url
```

### Option 2) **Database Pool**

```env
DATABASE_USER=your_database_username
DATABASE_HOST=your_database_host
DATABASE_PASSWORD=your_database_password
DATABASE_PORT=your_database_port (probably 5432)
DATABASE_NAME=your_database_name
```

AuthKit will use DATABASE_URL if it is present; otherwise it will fall back to the pool configuration.

## 3) AuthKit Entry Point (app/auth.ts):

Create app/auth.ts. This file instantiates AuthKit once and exposes strongly typed primitives across your application.

```ts
// app/auth.ts
import { AuthKit } from 'authkit';
import type { AuthConfig, DatabaseConfig } from 'authkit';

// If using pool-based configuration, parse the port from the env var.
const dbPort = process.env.DATABASE_PORT
	? parseInt(process.env.DATABASE_PORT, 10)
	: undefined;

// Pool-based configuration (used if DATABASE_URL is not set).
const databaseConfig: DatabaseConfig = {
	user: process.env.DATABASE_USER!,
	host: process.env.DATABASE_HOST!,
	password: process.env.DATABASE_PASSWORD!,
	port: dbPort!,
	name: process.env.DATABASE_NAME!,
};

// Main AuthKit configuration.
const config: AuthConfig = {
	options: {
		strategy: 'database', // current implementation uses database-backed sessions
	},
	db: process.env.DATABASE_URL ?? databaseConfig,
	providers: [
		{
			type: 'credentials',
			id: 'emailPassword',
			// Additional provider options (e.g. rate limiting) configured here if required.
		},
		// Example OIDC provider:
		// {
		//   type: "oidc",
		//   id: "google",
		//   issuer: "https://accounts.google.com",
		//   clientId: process.env.GOOGLE_CLIENT_ID!,
		//   clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
		//   redirectURI: "https://your-app.com/api/auth/provider/google/callback",
		// },
	],
	callbacks: {
		// Optional: override or extend behaviours here (e.g. profile mapping).
		// authorise: async (ctx, credentials) => { ... },
	},
};

// The factory returns App Router–ready primitives.
export const { handlers, auth, middleware } = AuthKit(config);
```

### TypeScript Path Alias (optional, recommended)

To make imports less verbose, add a path alias in your tsconfig.json:

```json
{
	"compilerOptions": {
		// ...
		"paths": {
			"@/auth": ["app/auth"]
		}
	}
}
```

This allows you to import from "@/auth" anywhere in your app.

## 4) Auth Route (app/api/auth/[...authkit]/route.ts):

AuthKit exposes request handlers for your authentication endpoints. In a typical setup you route both GET and POST to handlers returned by the factory.

Create app/api/auth/[...authkit]/route.ts:

```ts
// app/api/auth/[...authkit]/route.ts
import { handlers } from '@/auth';

/**
 * Main GET endpoint for AuthKit (e.g., OAuth callbacks, session retrieval).
 */
export const GET = handlers.GET;

/**
 * Main POST endpoint for AuthKit (e.g., credential login/register).
 */
export const POST = handlers.POST;
```

If you prefer a different route structure, you can re-export handlers.GET / handlers.POST from whatever path you choose, as long as it is consistent with the redirect URIs configured for OIDC providers.

## 5) Middleware Integration (proxy.ts):

AuthKit provides middleware to protect routes and enforce role‑based access control.

Create or update proxy.ts in the project root:

```ts
// proxy.ts
import { middleware as withAuthMiddleware } from '@/auth';

export const config = {
	// Define the set of routes that should run through this middleware.
	// Adjust this to match your application.
	matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};

export default withAuthMiddleware({
	// Routes that do NOT require authentication.
	publicRoutes: ['/login', '/register'],

	// Route to redirect unauthenticated users to.
	loginRoute: '/login',

	// Optional role-based rules.
	// Example: restrict /admin to users with the "admin" role.
	roleRules: [
		{
			pattern: /^\/admin/,
			requiredRoles: ['admin'],
			mode: 'all', // "any" or "all"
		},
	],
});
```

This middleware checks for a valid session cookie, retrieves the session when possible, and enforces any role rules you define. Public routes are always allowed through.

## 6. Database Setup and Migrations:

AuthKit assumes a PostgreSQL schema matching its internal user, session, and account models. The library ships with Drizzle migrations and a Drizzle configuration so you can apply the schema automatically.

You have two options:

- Drizzle migrations (recommended)
- Manual SQL migrations (psql / PowerShell)

### 6.1) Drizzle Migrations (recommended):

1. Ensure you have drizzle-orm and drizzle-kit installed in your Next.js project.
2. From your project root, run:

```bash
npx drizzle-kit migrate:pg --config ./node_modules/authkit/drizzle.config.ts
```

This command applies all migrations located under ./node_modules/authkit/drizzle/ to the database described by your DATABASE_URL or pool config.

If you see harmless errors like relation ... already exists, it usually indicates that a migration step has already been applied.

### 6.2) Manual Migrations (SQL files):

If you prefer to run the SQL scripts yourself, you can apply the bundled .sql files directly.

#### Locate the migration files:

All migration scripts are shipped under:

```text
./node_modules/authkit/drizzle/
```

They are numbered for ordering, for example:

```text
0000_initial.sql
0001_add_accounts_table.sql
0002_update_users.sql
...
0015_latest_change.sql
```

#### Unix-like shells (bash/zsh):

Make sure psql is installed and your database URL is available.

```bash
# Replace YOUR_DATABASE_URL with your real connection string.
for file in ./node_modules/authkit/drizzle/*.sql; do
  psql "YOUR_DATABASE_URL" -f "$file"
done
```

Example:

```bash
for file in ./node_modules/authkit/drizzle/*.sql; do
  psql "postgresql://user:password@localhost:5432/mydb" -f "$file"
done
```

#### PowerShell (Windows):

In PowerShell, you can achieve the same loop with:

```powershell
$files = Get-ChildItem -Path ".\node_modules\authkit\drizzle\*.sql" | Sort-Object Name
$connectionString = "YOUR_DATABASE_URL"

foreach ($file in $files) {
  & psql $connectionString -f $file.FullName
}
```

Example:

```powershell
$files = Get-ChildItem -Path ".\node_modules\authkit\drizzle\*.sql" | Sort-Object Name
$connectionString = "postgresql://user:password@localhost:5432/mydb"

foreach ($file in $files) {
  & psql $connectionString -f $file.FullName
}
```

#### Important notes for manual migration:
* Run all migration files in order. Do not skip earlier migrations or run only the highest-numbered file.

* If you see errors such as relation ... already exists, they usually indicate that the migration step has already been applied and can be safely ignored.

* If you see schema mismatch errors from AuthKit at runtime, re-run the migration loop to ensure your schema matches the version shipped with the library.

* Always back up your database before applying migrations.

## 7) Summary:
At minimum, to get AuthKit running you must:

1) Provide PostgreSQL connection details via .env.

2) Create app/auth.ts and instantiate AuthKit(config).

3) Wire up app/api/auth/[...authkit]/route.ts with handlers.GET and handlers.POST.

4) Configure middleware.ts with withAuthMiddleware if you want middleware-based route protection.

5) Apply the shipped database migrations via Drizzle or manual SQL.

From there, you can add OIDC providers, customise callbacks, and extend role‑based access control as your application requires.

Happy shipping!

# AuthKit Usage Guide

AuthKit is a modular authentication library for the Next.js App Router. It provides:

- Credential-based authentication (email/password)
- OAuth 2.1/OIDC providers (e.g. Google, custom OIDC)
- Server-side sessions backed by PostgreSQL
- Middleware-based route protection and RBAC
- Typed client and server helpers for the App Router

This guide assumes you have already initialised AuthKit as described above (environment variables, app/auth.ts, routes, and migrations).

## 1. Server-Side Usage

All server-side APIs are exposed via your app/auth.ts entry point.

Example app/auth.ts:

import { AuthKit } from "authkit";
import type { AuthConfig, DatabaseConfig } from "authkit";

// If using pool-based configuration, parse the port from the env var.
const dbPort = process.env.DATABASE_PORT
  ? parseInt(process.env.DATABASE_PORT, 10)
  : undefined;

// Pool-based configuration (used if DATABASE_URL is not set).
const databaseConfig: DatabaseConfig = {
  user: process.env.DATABASE_USER!,
  host: process.env.DATABASE_HOST!,
  password: process.env.DATABASE_PASSWORD!,
  port: dbPort!,
  name: process.env.DATABASE_NAME!,
};

// Main AuthKit configuration.
const config: AuthConfig = {
  options: {
    strategy: "database",
  },
  db: process.env.DATABASE_URL ?? databaseConfig,
  providers: [
    {
      type: "credentials",
      id: "emailPassword",
    },
    // Example OIDC provider:
    // {
    //   type: "oidc",
    //   id: "google",
    //   issuer: "https://accounts.google.com",
    //   clientId: process.env.GOOGLE_CLIENT_ID!,
    //   clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    //   redirectURI: "https://your-app.com/api/auth/google/callback",
    // },
  ],
  callbacks: {
    // Optional: override or extend behaviours here.
  },
};

export const { handlers, auth, middleware } = AuthKit(config);

### 1.1 auth – Getting the Current Session (Server Components / Route Handlers)

auth is the primary server-side helper. It reads the session cookie, validates the session, applies TTL logic, and returns the current session plus user (or null).

Usage in a Server Component:

```ts
import { auth } from "authkit/server";
import { redirect } from "next/navigation";

export default async function DashboardPage() {
  const session = await auth();

  if (!session || !session.user) {
    redirect("/login");
  }

  return (
    <main>
      <h1>Welcome, {session.user.name}</h1>
      <p>Your roles: {session.user.roles.join(", ")}</p>
    </main>
  );
}
```

Usage in a Route Handler:

```ts
import { auth } from "authkit/server";
import { NextResponse } from "next/server";

export async function GET() {
  const session = await auth();

  if (!session || !session.user) {
    return new NextResponse("Unauthorised", { status: 401 });
  }

  return NextResponse.json({ user: session.user });
}
```

### 1.2 Session Operations (Rotation, Privilege Updates)

Typical patterns:

- Reading the session: auth()
- Rotating the session: e.g. after privilege changes
- Updating password/privileges: via updatePassword / updatePrivalege public functions

Example privilege update route (adjust imports to match your export surface):

```ts
import { auth, updatePrivalege } from "authkit/server";
import { NextRequest, NextResponse } from "next/server";

export async function POST(request: NextRequest, { params }: { params: { id: string } }) {
  const session = await auth();

  if (!session || !session.user || !session.user.roles.includes("admin")) {
    return new NextResponse("Forbidden", { status: 403 });
  }

  const body = await request.json() as { roles: string[] };
  await updatePrivalege({ userId: params.id, roles: body.roles });

  return new NextResponse(null, { status: 204 });
}
```

## 2. Middleware Usage

AuthKit’s middleware integrates at the Next.js middleware.ts entry point and enforces:

- Authentication presence (session cookie + valid session)
- Public vs protected routes
- Role-based access control via roleRules

### 2.1 Basic Middleware Setup

Example proxy.ts:

```ts
import { middleware as withAuthMiddleware } from "authkit/middleware";

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};

export default withAuthMiddleware({
  publicRoutes: ["/login", "/register"],
  loginRoute: "/login",
});
```

This configuration:

- Allows /login and /register through without a session.
- For any other route:
  - Checks for a valid session cookie.
  - Loads the session.
  - Redirects unauthenticated users to /login?redirectTo=<originalPath>.

### 2.2 Role-Based Access Control in Middleware

You can enforce RBAC at the URL level using roleRules.

Example:

```ts
import { middleware as withAuthMiddleware } from "authkit/middleware";

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};

export default withAuthMiddleware({
  publicRoutes: ["/login", "/register"],
  loginRoute: "/login",
  roleRules: [
    {
      pattern: /^\/admin/,
      requiredRoles: ["admin"],
      mode: "all", // "any" or "all"
    },
    {
      pattern: /^\/billing/,
      requiredRoles: ["billing", "admin"],
      mode: "any",
    },
  ],
});
```

If a user reaches a matching path and lacks the required roles, they are redirected to loginRoute with redirectTo pointing back to the original path.

## 3. Auth Routes (Built-In Handlers)

AuthKit exposes route handlers under handlers for:

- Credential login/register
- OIDC authorise/callback
- Session retrieval/deletion

You usually wire them through app/api/auth/[...authkit]/route.ts:

```ts
import { handlers } from "@/auth";

export const GET = handlers.GET;
export const POST = handlers.POST;
```

Internally, these handlers route:

- /api/auth/provider/emailPassword/login to credential login
- /api/auth/provider/emailPassword/register to credential registration
- /api/auth/provider/:providerId/authorize to the OIDC authorisation endpoint
- /api/auth/provider/:providerId/callback to the OIDC callback handler
- /api/auth/session (GET/DELETE) to session retrieval and logout

You do not need to implement these flows yourself; they are generated by AuthKit based on your providers config.

## 4. Client-Side Usage (Low-Level Helpers)

Client helpers are exported via the client surface of the library.

### 4.1 ClientSession – Raw Client Session Helpers

ClientSession wraps direct HTTP calls to the session endpoints.

- ClientSession.getAuth() – GET /api/auth/session, returns SessionWithUser | null.
- ClientSession.deleteSession() – DELETE /api/auth/session, CSRF-protected.

Example:

```ts
import { session as ClientSession } from "authkit/client";

useEffect(() => {
  ClientSession.getAuth().then((session) => {
    // ...
  });
}, []);
```

### 4.2 ClientAuth – Credential Auth Helpers

ClientAuth exposes lower-level methods for credential auth:

- ClientAuth.emailPassword.login(email, password)
- ClientAuth.emailPassword.register(userConfig, password)

You normally use the React hooks instead, but these are available if you prefer direct calls.

## 5. React Hooks

All hooks assume Next.js App Router and React on the client.

### 5.1 useAuth – Read Session State on the Client

```ts
import { useAuth } from "authkit/client";

export function Profile() {
  const { session, loading } = useAuth();

  if (loading) return <p>Loading...</p>;
  if (!session?.user) return <p>You are not signed in.</p>;

  return <p>Signed in as {session.user.email}</p>;
}
```

useAuth fetches the current session via ClientSession.getAuth() and exposes { session, loading }.

### 5.2 useAuthGuard – Client-Side Guard with RBAC

useAuthGuard uses useAuth under the hood and can redirect or call a callback if the user is unauthorised.

```ts
import { useAuthGuard } from "authkit/client";

export default function AdminPage() {
  const { session, loading, hasAccess } = useAuthGuard(["admin"], {
    redirectTo: "/login",
    onUnauthorised: () => {
      console.warn("Unauthorised access attempt");
    },
    mode: "all", // "any" or "all"
  });

  if (loading) return <p>Loading...</p>;
  if (!hasAccess) return null;

  return <div>Welcome, {session?.user?.name}. You are an admin.</div>;
}
```

useAuthGuard(requiredRoles, options) returns:

- session
- loading
- hasAccess
- hasRole(role)
- hasAnyRole(roles)
- hasAllRoles(roles)

### 5.3 useEmailPasswordLogin – Log In with Email/Password

```ts
import { useEmailPasswordLogin } from "authkit/client";

export function LoginForm() {
  const { login, loading, error } = useEmailPasswordLogin();

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const email = String(formData.get("email"));
    const password = String(formData.get("password"));

    try {
      const { user, session } = await login(email, password);
      // Redirect or update state
    } catch (err) {
      // error state already set
    }
  }

  return (
    <form onSubmit={onSubmit}>
      {/* fields */}
      {error && <p>{error.message}</p>}
      <button type="submit" disabled={loading}>
        Sign in
      </button>
    </form>
  );
}
```

### 5.4 useEmailPasswordRegister – Register New Users

```ts
import { useEmailPasswordRegister } from "authkit/client";
import type { NewUserClient } from "authkit";

export function RegisterForm() {
  const { register, loading, error } = useEmailPasswordRegister();

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);

    const userConfig: NewUserClient = {
      name: String(formData.get("name")),
      email: String(formData.get("email")),
      username: String(formData.get("username") ?? ""),
    };

    const password = String(formData.get("password"));

    try {
      const { user, session } = await register(userConfig, password);
      // Redirect or update state
    } catch (err) {
      // handle error
    }
  }

  return (
    <form onSubmit={onSubmit}>
      {/* fields */}
      {error && <p>{error.message}</p>}
      <button type="submit" disabled={loading}>
        Register
      </button>
    </form>
  );
}
```

### 5.5 useProviderLogIn – OIDC Provider Login (e.g. Google)

```ts
import { useProviderLogIn } from "authkit/client";

export function SocialLogin() {
  const { logIn, loading, error } = useProviderLogIn();

  async function signInWithGoogle() {
    await logIn("google", "/dashboard"); // providerId, redirectTo
  }

  return (
    <div>
      {error && <p>{error.message}</p>}
      <button onClick={signInWithGoogle} disabled={loading}>
        Continue with Google
      </button>
    </div>
  );
}
```

logIn(providerId, redirectTo?) builds the authorisation URL for the provider, appends redirectTo into state where supported, and sets window.location.href to start the OAuth flow.

### 5.6 useLogout – Log Out (CSRF-Protected)

```ts
import { useLogout } from "authkit/client";

export function LogoutButton() {
  const { logout, loading, error } = useLogout();

  async function handleLogout() {
    try {
      await logout();
      // Optionally do client-side redirect here as well.
    } catch (err) {
      // handle error
    }
  }

  return (
    <>
      {error && <p>{error.message}</p>}
      <button onClick={handleLogout} disabled={loading}>
        Logout
      </button>
    </>
  );
}
```

useLogout:

- Reads the CSRF cookie set at login.
- Sends a DELETE request to /api/auth/session with the CSRF header.
- On success, clears session cookies and navigates to login by default.

## 6. Putting It Together

A typical integration looks like this:

1. Initialise AuthKit in app/auth.ts with DB config and providers.
2. Wire routes: app/api/auth/[...authkit]/route.ts with handlers.GET and handlers.POST.
3. Add middleware: middleware.ts using withAuthMiddleware for auth and RBAC.
4. Use server helper: call await auth() in Server Components and Route Handlers.
5. Use hooks on the client: useAuth, useAuthGuard, useEmailPasswordLogin, useEmailPasswordRegister, useProviderLogIn, useLogout.

With that in place, you have:

- Server-side rendered pages that know the current user.
- API routes that can enforce auth/roles.
- Middleware that blocks unauthenticated/unauthorised requests early.
- A client hook layer that gives you predictable login/register/logout flows without exposing CSRF or low-level session details.