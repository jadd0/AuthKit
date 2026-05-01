import { describe, it, expect } from "vitest";
import { z } from "zod";

const PS = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("credentials"),
    id: z.string(),
    saltingRounds: z.number().int().min(8).max(14).optional(),
  }),
  z.object({
    type: z.literal("oidc"),
    id: z.string(),
    issuer: z.string().url("Issuer must be a valid URL"),
    clientId: z.string().min(1),
    clientSecret: z.string().min(1),
    redirectURI: z.string().url(),
    scopes: z.array(z.string()).min(1),
  }),
]);
const ACS = z.object({
  db: z.string().min(1, "Database URL is required"),
  providers: z.array(PS).min(1, "At least one provider is required"),
  options: z.object({
    CSRFSecret: z.string().min(32, "CSRFSecret must be at least 32 characters"),
    sameSite: z.enum(["Strict", "Lax", "None"]).optional(),
    idleTTL: z.number().positive().optional(),
    absoluteTTL: z.number().positive().optional(),
  }),
});
function val(c: unknown): { success: boolean; error?: string } {
  const r = ACS.safeParse(c);
  if (r.success) return { success: true };
  return {
    success: false,
    error: r.error.errors
      .map((e) => `${e.path.join(".")}: ${e.message}`)
      .join("; "),
  };
}
function init(c: unknown): void {
  const r = val(c);
  if (!r.success)
    throw new Error(
      `AuthKit failed to start: invalid configuration — ${r.error}`,
    );
}

const V = {
  db: "postgresql://localhost:5432/authkit_test",
  providers: [
    { type: "credentials" as const, id: "emailPassword", saltingRounds: 10 },
  ],
  options: {
    CSRFSecret: "a-valid-csrf-secret-that-is-long-enough!",
    sameSite: "Strict" as const,
  },
};

describe("Valid configuration", () => {
  it("accepts a fully valid config", () => {
    expect(val(V).success).toBe(true);
  });
  it("accepts a config with OIDC provider", () => {
    expect(
      val({
        ...V,
        providers: [
          {
            type: "oidc",
            id: "g",
            issuer: "https://accounts.google.com",
            clientId: "c",
            clientSecret: "s",
            redirectURI: "https://app.com/cb",
            scopes: ["openid"],
          },
        ],
      }).success,
    ).toBe(true);
  });
});

describe("Missing CSRFSecret", () => {
  it("fails when CSRFSecret absent", () => {
    expect(
      val({ ...V, options: { ...V.options, CSRFSecret: undefined } }).success,
    ).toBe(false);
  });
  it("fails when CSRFSecret shorter than 32 chars", () => {
    const r = val({ ...V, options: { ...V.options, CSRFSecret: "tooshort" } });
    expect(r.success).toBe(false);
    expect(r.error).toContain("32 characters");
  });
});

describe("No providers supplied", () => {
  it("fails when providers array empty", () => {
    const r = val({ ...V, providers: [] });
    expect(r.success).toBe(false);
    expect(r.error).toContain("provider");
  });
  it("fails when providers key missing", () => {
    const { providers: _, ...n } = V;
    expect(val(n).success).toBe(false);
  });
});

describe("Malformed OIDC issuer", () => {
  it("fails when issuer is not a valid URL", () => {
    const r = val({
      ...V,
      providers: [
        {
          type: "oidc",
          id: "g",
          issuer: "not-a-url",
          clientId: "c",
          clientSecret: "s",
          redirectURI: "https://app.com/cb",
          scopes: ["openid"],
        },
      ],
    });
    expect(r.success).toBe(false);
    expect(r.error?.toLowerCase()).toContain("issuer");
  });
});

describe("Unknown SameSite value", () => {
  it("fails for unsupported sameSite", () => {
    expect(
      val({ ...V, options: { ...V.options, sameSite: "Invalid" as any } })
        .success,
    ).toBe(false);
  });
});

describe("Missing database URL", () => {
  it("fails when db is empty", () => {
    const r = val({ ...V, db: "" });
    expect(r.success).toBe(false);
    expect(r.error).toContain("db");
  });
});

describe("Startup throw behaviour", () => {
  it("throws for short CSRFSecret", () => {
    expect(() =>
      init({ ...V, options: { ...V.options, CSRFSecret: "short" } }),
    ).toThrow("AuthKit failed to start");
  });
  it("throws for empty providers", () => {
    expect(() => init({ ...V, providers: [] })).toThrow(
      "AuthKit failed to start",
    );
  });
  it("throws with descriptive message", () => {
    try {
      init({ ...V, providers: [] });
    } catch (e: any) {
      expect(e.message).toContain("invalid configuration");
    }
  });
  it("does NOT throw for valid config", () => {
    expect(() => init(V)).not.toThrow();
  });
});
