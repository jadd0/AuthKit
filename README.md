# PROJECT INITIALISATION:

Create a Next.js app normally with:
```console
npx create-next-app@latest
```

The following describes the recommended approach to instantiating the library.

### ENV:

The .env file should contain the database credentials in either of the following ways, the credentials should be easily found in your database display app.

1) **Database URL (RECOMMENDED):**
```env
DATABASE_URL: your_database_url
```

2) **Database Pool**
```env
DATABASE_USER: your_database_username
DATABASE_HOST: your_database_host
DATABASE_PASSWORD: your_database_password
DATABASE_PORT: your_database_port
```

# FILE STRUCTURE:

## /app/auth.ts:
This is the main entry point to the library. AuthKit is instantiated in here and exposed project-wide. 

This is the general structure of the file, including explanations for everything:

```typescript
import { AuthKit } from "authkit";
import type { AuthConfig, DatabaseConfig } from "authkit";

// Database object, choose only if using database Pool.

// THIS IS ONLY NECESSARY IF PORT IS THROWING A TYPE ERROR FOR PORT BEING A STRING
const dbPort = parseInt(process.env.DATABASE_PORT!);

/** Strongly typed database config object for database Pool */
const database = {
  user: process.env.DATABASE_USER!,
  host: process.env.DATABASE_USER!,
  password: process.env.DATABASE_USER!,
  port: dbPort,
  name: process.env.DATABASE_NAME!,
} satisfies DatabaseConfig;

// Strongly typed AuthKit config
const config = {
  options: { strategy: "database" }, // or "jwt"
  db: process.env.DATABASE_URL! || database, // YOUR CHOICE, depends on your desire to use url/pool
  providers: [
    { type: "credentials", id: "emailPassword" },
    // { type: "oidc", issuer: "...", clientId: "...", clientSecret: "...", redirectUri: "..." }
  ],
  callbacks: {
    // authorise: async (ctx, credentials) => { /* return { userId } or null */ },
  },
} satisfies AuthConfig;

// The factory returns App Router–ready primitives
export const { handlers, auth, signOut } = AuthKit(config);
```

We recommend adding the following to your tsconfig.json for ease of access:

Inside "compilerOptions":
```json
  "paths": {
    ...
    "@/auth": ["app/auth"]
  }
```

This will allow an easy alias to the main auth file from anywhere in your app.


## /app/api/auth/[...authkit]/route.ts:
This is the main endpoint for any auth callbacks. You may route this however you want, however this is the recommended blueprint:

```typescript
import { handlers } from "@/auth";

/** This acts as the main GET request endpoint */
export const GET = handlers.GET;

/** This acts as the main POST request endpoint */
export const POST = handlers.POST;
```

However you choose to route from here is up to you.

# DATABASE SETUP:

To use AuthKit, you must ensure your database schema is up-to-date with the provided migration files.

AuthKit has been developed using Drizzle ORM (<link href="https://orm.drizzle.team">Drizzle</link>), so naturally we will recommend you to use the same. However, we also provide a manual PostgreSQL migration script.

Choose one of the following to migrate the database schema in a one line command.

## DRIZZLE MIGRATION:

1. Ensure you have drizzle-orm and drizzle-kit installed.

2. In your project root, run:

```console
npx drizzle-kit migrate:pg --config ./node_modules/authkit/drizzle.config.ts
```

This automatically applies all migrations in the drizzle/ folder shipped with the library.

## MANUAL MIGRATION:

To keep your database schema up to date, **run all migration files in order**.

1. **Locate migration files:**

```
./node_modules/authkit/drizzle/
```

Migration filenames are numbered for order, for example:

```
0000_initial.sql
0001_add_accounts_table.sql
0002_update_users.sql
...
0015_latest_change.sql
```

2. **Run each migration in order:**

(where [YOUR_DATABASE_URL is your database URL])

```console
for file in ./node_modules/authkit/drizzle/*.sql; do
  psql YOUR_DATABASE_URL -f "$file"
done
```

- This safely updates your database whether you are initialising or upgrading.
- Harmless errors like `"relation ... already exists"` just mean a migration step has already been applied.

For manual users, if an error is thrown stating that your schema does not match, try running the above.

**ALWAYS BACK UP YOUR DATABASE BEFORE APPLYING MIGRATIONS, JUST IN CASE.**

**Important:**

- Do not skip any migration files.
- Do not run only the last or highest-numbered migration; all must be applied in order.
- If you see schema mismatch errors, double-check your table and column types match the expected migrations.
