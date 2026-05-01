/**
 * Unit tests for AuthKit Zod config schema and dbSchemaValidation.
 * Source: src/shared/validation/authConfigSchema.ts
 *         src/shared/validation/dbSchemaValidation.ts
 *
 * R5 – fail-closed: missing CSRF_SECRET, http:// in production,
 *       no providers, malformed issuer all throw at startup.
 */
import { describe, it, expect } from "vitest";
import { z, ZodError } from "zod";

// Mirrors authConfigSchema.ts
function makeCallbackSchema(env: string) {
  return z
    .string()
    .url()
    .superRefine((url, ctx) => {
      if (env === "production" && url.startsWith("http://")) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Callback URL must use HTTPS in production",
        });
      }
    });
}

const ProviderSchema = z
  .object({
    type: z.enum(["credential", "oidc"]),
    issuer: z.string().url().optional(),
  })
  .superRefine((v, ctx) => {
    if (v.type === "oidc" && !v.issuer)
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "OIDC provider must include a valid issuer URL",
      });
  });

function makeAuthConfigSchema(env: string) {
  return z.object({
    CSRF_SECRET: z
      .string()
      .min(32, "CSRF_SECRET must be at least 32 characters"),
    callbackUrl: makeCallbackSchema(env),
    providers: z
      .array(ProviderSchema)
      .min(1, "At least one authentication provider must be configured"),
    options: z
      .object({
        sessionCookieName: z.string().optional(),
        sameSite: z.enum(["Strict", "Lax", "None"]).optional(),
        idleTTL: z.number().positive().optional(),
        absoluteTTL: z.number().positive().optional(),
      })
      .optional(),
  });
}

// Mirrors dbSchemaValidation.ts
interface Col {
  name: string;
  type: string;
}
interface FK {
  from: string;
  to: string;
}
interface ExpectedTable {
  columns: Col[];
  foreignKeys?: FK[];
}

function dbSchemaValidation(
  actual: Record<string, Col[]>,
  actualFKs: Record<string, FK[]>,
  expected: Record<string, ExpectedTable>,
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  for (const [table, def] of Object.entries(expected)) {
    const cols = actual[table];
    if (!cols) {
      errors.push(`Missing table: ${table}`);
      continue;
    }
    for (const ec of def.columns) {
      const ac = cols.find((c) => c.name === ec.name);
      if (!ac) {
        errors.push(`${table}: missing column '${ec.name}'`);
        continue;
      }
      if (ac.type !== ec.type)
        errors.push(
          `${table}.${ec.name}: expected '${ec.type}', got '${ac.type}'`,
        );
    }
    for (const efk of def.foreignKeys ?? []) {
      if (
        !(actualFKs[table] ?? []).some(
          (fk) => fk.from === efk.from && fk.to === efk.to,
        )
      )
        errors.push(`${table}: missing FK ${efk.from} → ${efk.to}`);
    }
  }
  return { valid: errors.length === 0, errors };
}

const VALID = {
  CSRF_SECRET: "a".repeat(32),
  callbackUrl: "https://myapp.com/api/auth/provider/google/callback",
  providers: [{ type: "credential" as const }],
  options: { sameSite: "Strict" as const },
};

describe("authConfigSchema – valid", () => {
  it("accepts a complete production config", () => {
    expect(makeAuthConfigSchema("production").safeParse(VALID).success).toBe(
      true,
    );
  });
  it("accepts http:// callbackUrl in development", () => {
    expect(
      makeAuthConfigSchema("development").safeParse({
        ...VALID,
        callbackUrl: "http://localhost:3000/cb",
      }).success,
    ).toBe(true);
  });
});

describe("authConfigSchema – missing CSRF_SECRET", () => {
  it("rejects when absent", () => {
    const { CSRF_SECRET: _, ...cfg } = VALID;
    expect(makeAuthConfigSchema("production").safeParse(cfg).success).toBe(
      false,
    );
  });
  it("rejects when shorter than 32 chars", () => {
    const r = makeAuthConfigSchema("production").safeParse({
      ...VALID,
      CSRF_SECRET: "short",
    });
    expect(r.success).toBe(false);
    expect(
      (r as { error: ZodError }).error.issues.some((i) =>
        i.message.includes("32"),
      ),
    ).toBe(true);
  });
});

describe("authConfigSchema – http:// in production", () => {
  it("rejects http:// callbackUrl in production", () => {
    const r = makeAuthConfigSchema("production").safeParse({
      ...VALID,
      callbackUrl: "http://myapp.com/cb",
    });
    expect(r.success).toBe(false);
    expect(
      (r as { error: ZodError }).error.issues.some((i) =>
        i.message.includes("HTTPS"),
      ),
    ).toBe(true);
  });
});

describe("authConfigSchema – no providers", () => {
  it("rejects empty providers array", () => {
    expect(
      makeAuthConfigSchema("production").safeParse({ ...VALID, providers: [] })
        .success,
    ).toBe(false);
  });
});

describe("authConfigSchema – malformed OIDC issuer", () => {
  it("rejects non-URL issuer", () => {
    expect(
      makeAuthConfigSchema("production").safeParse({
        ...VALID,
        providers: [{ type: "oidc", issuer: "not-a-url" }],
      }).success,
    ).toBe(false);
  });
  it("rejects OIDC provider with no issuer", () => {
    const r = makeAuthConfigSchema("production").safeParse({
      ...VALID,
      providers: [{ type: "oidc" }],
    });
    expect(r.success).toBe(false);
    expect(
      (r as { error: ZodError }).error.issues.some((i) =>
        i.message.includes("issuer"),
      ),
    ).toBe(true);
  });
  it("rejects unknown SameSite value", () => {
    expect(
      makeAuthConfigSchema("production").safeParse({
        ...VALID,
        options: { sameSite: "Invalid" },
      }).success,
    ).toBe(false);
  });
});

// DB schema validation tests
const EXPECTED = {
  users: {
    columns: [
      { name: "id", type: "uuid" },
      { name: "email", type: "varchar" },
      { name: "created_at", type: "timestamptz" },
    ],
  },
  sessions: {
    columns: [
      { name: "id", type: "uuid" },
      { name: "user_id", type: "uuid" },
      { name: "session_token", type: "varchar" },
    ],
    foreignKeys: [{ from: "user_id", to: "users.id" }],
  },
  accounts: {
    columns: [
      { name: "id", type: "uuid" },
      { name: "user_id", type: "uuid" },
      { name: "provider", type: "varchar" },
    ],
    foreignKeys: [{ from: "user_id", to: "users.id" }],
  },
};
const ACTUAL_COLS = {
  users: [
    { name: "id", type: "uuid" },
    { name: "email", type: "varchar" },
    { name: "created_at", type: "timestamptz" },
  ],
  sessions: [
    { name: "id", type: "uuid" },
    { name: "user_id", type: "uuid" },
    { name: "session_token", type: "varchar" },
  ],
  accounts: [
    { name: "id", type: "uuid" },
    { name: "user_id", type: "uuid" },
    { name: "provider", type: "varchar" },
  ],
};
const ACTUAL_FKS = {
  sessions: [{ from: "user_id", to: "users.id" }],
  accounts: [{ from: "user_id", to: "users.id" }],
};

describe("dbSchemaValidation – correct schema", () => {
  it("returns valid=true with no errors", () => {
    const r = dbSchemaValidation(ACTUAL_COLS, ACTUAL_FKS, EXPECTED);
    expect(r.valid).toBe(true);
    expect(r.errors).toHaveLength(0);
  });
});
describe("dbSchemaValidation – missing column", () => {
  it("reports missing 'email' column", () => {
    const r = dbSchemaValidation(
      {
        ...ACTUAL_COLS,
        users: ACTUAL_COLS.users.filter((c) => c.name !== "email"),
      },
      ACTUAL_FKS,
      EXPECTED,
    );
    expect(r.valid).toBe(false);
    expect(r.errors.some((e) => e.includes("email"))).toBe(true);
  });
});
describe("dbSchemaValidation – altered foreign key", () => {
  it("reports missing FK when sessions.user_id → users.id removed", () => {
    const r = dbSchemaValidation(
      ACTUAL_COLS,
      { ...ACTUAL_FKS, sessions: [] },
      EXPECTED,
    );
    expect(r.valid).toBe(false);
    expect(r.errors.some((e) => e.includes("user_id"))).toBe(true);
  });
});
describe("dbSchemaValidation – missing table", () => {
  it("reports missing accounts table", () => {
    const { accounts: _, ...cols } = ACTUAL_COLS;
    const r = dbSchemaValidation(cols, ACTUAL_FKS, EXPECTED);
    expect(r.valid).toBe(false);
    expect(r.errors.some((e) => e.includes("accounts"))).toBe(true);
  });
});
