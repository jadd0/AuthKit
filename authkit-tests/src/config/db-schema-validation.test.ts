import { describe, it, expect } from "vitest";

interface SC {
  name: string;
  type: string;
}
interface ST {
  columns: SC[];
  foreignKeys?: { column: string; references: string }[];
}
interface DS {
  users: ST;
  sessions: ST;
  accounts: ST;
}

const ES: DS = {
  users: {
    columns: [
      { name: "id", type: "varchar" },
      { name: "email", type: "varchar" },
      { name: "name", type: "varchar" },
      { name: "roles", type: "text[]" },
      { name: "createdAt", type: "timestamp" },
      { name: "updatedAt", type: "timestamp" },
    ],
  },
  sessions: {
    columns: [
      { name: "id", type: "varchar" },
      { name: "sessionToken", type: "varchar" },
      { name: "userId", type: "varchar" },
      { name: "createdAt", type: "timestamp" },
      { name: "lastActivityAt", type: "timestamp" },
    ],
    foreignKeys: [{ column: "userId", references: "users.id" }],
  },
  accounts: {
    columns: [
      { name: "userId", type: "varchar" },
      { name: "provider", type: "varchar" },
      { name: "type", type: "varchar" },
      { name: "createdAt", type: "timestamp" },
      { name: "updatedAt", type: "timestamp" },
    ],
    foreignKeys: [{ column: "userId", references: "users.id" }],
  },
};

function validate(a: DS, e: DS): void {
  for (const [tn, et] of Object.entries(e) as [keyof DS, ST][]) {
    const at = a[tn];
    if (!at)
      throw new Error(
        `Database schema validation failed: table '${tn}' is missing`,
      );
    for (const c of et.columns)
      if (!at.columns.find((x) => x.name === c.name))
        throw new Error(
          `Database schema validation failed: column '${c.name}' missing from table '${tn}'`,
        );
    if (et.foreignKeys)
      for (const fk of et.foreignKeys)
        if (
          !at.foreignKeys?.find(
            (f) => f.column === fk.column && f.references === fk.references,
          )
        )
          throw new Error(
            `Database schema validation failed: foreign key '${fk.column} → ${fk.references}' missing from '${tn}'`,
          );
  }
}

const cp = <T>(x: T): T => JSON.parse(JSON.stringify(x));

describe("dbSchemaValidation — correct schema", () => {
  it("passes when schema matches exactly", () => {
    expect(() => validate(ES, ES)).not.toThrow();
  });
  it("passes when actual has extra columns (additive migrations safe)", () => {
    const e = cp(ES);
    e.users.columns.push({ name: "phone", type: "varchar" });
    expect(() => validate(e, ES)).not.toThrow();
  });
});

describe("dbSchemaValidation — missing columns", () => {
  it("throws when roles missing from users", () => {
    const b = cp(ES);
    b.users.columns = b.users.columns.filter((c: SC) => c.name !== "roles");
    expect(() => validate(b, ES)).toThrow(
      "column 'roles' missing from table 'users'",
    );
  });
  it("throws when sessionToken missing from sessions", () => {
    const b = cp(ES);
    b.sessions.columns = b.sessions.columns.filter(
      (c: SC) => c.name !== "sessionToken",
    );
    expect(() => validate(b, ES)).toThrow("column 'sessionToken'");
  });
  it("throws when lastActivityAt missing from sessions", () => {
    const b = cp(ES);
    b.sessions.columns = b.sessions.columns.filter(
      (c: SC) => c.name !== "lastActivityAt",
    );
    expect(() => validate(b, ES)).toThrow("column 'lastActivityAt'");
  });
  it("throws when provider missing from accounts", () => {
    const b = cp(ES);
    b.accounts.columns = b.accounts.columns.filter(
      (c: SC) => c.name !== "provider",
    );
    expect(() => validate(b, ES)).toThrow("column 'provider'");
  });
});

describe("dbSchemaValidation — broken foreign keys", () => {
  it("throws when userId FK missing from sessions", () => {
    const b = cp(ES);
    b.sessions.foreignKeys = [];
    expect(() => validate(b, ES)).toThrow("foreign key");
  });
  it("throws when userId FK references wrong table", () => {
    const b = cp(ES);
    b.sessions.foreignKeys = [{ column: "userId", references: "other.id" }];
    expect(() => validate(b, ES)).toThrow("foreign key");
  });
  it("throws when userId FK missing from accounts", () => {
    const b = cp(ES);
    b.accounts.foreignKeys = [];
    expect(() => validate(b, ES)).toThrow("foreign key");
  });
});

describe("dbSchemaValidation — missing tables", () => {
  it("throws when users table missing", () => {
    const b = cp(ES) as any;
    delete b.users;
    expect(() => validate(b, ES)).toThrow("table 'users' is missing");
  });
  it("throws when sessions table missing", () => {
    const b = cp(ES) as any;
    delete b.sessions;
    expect(() => validate(b, ES)).toThrow("table 'sessions' is missing");
  });
});

describe("Fail-closed: AuthKit refuses to start on bad schema", () => {
  it("throws at boot when schema broken", () => {
    const b = cp(ES);
    b.sessions.columns = b.sessions.columns.filter(
      (c: SC) => c.name !== "sessionToken",
    );
    expect(() => validate(b, ES)).toThrow("Database schema validation failed");
  });
  it("boots successfully when schema correct", () => {
    expect(() => validate(ES, ES)).not.toThrow();
  });
});
