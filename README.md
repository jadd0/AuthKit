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