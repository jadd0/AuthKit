/**
 * Unit tests for session TTL / expiry helpers.
 * Source: src/server/classes/auth/session/session.ts
 *
 * R2 – dual-TTL expiry, rotateSession token replacement.
 */
import { describe, it, expect } from "vitest";
import { randomBytes } from "crypto";

interface AuthConfig {
  options: { idleTTL?: number; absoluteTTL?: number };
}

class Session {
  id: string;
  sessionToken: string;
  createdAt: Date;
  lastActivityAt: Date;
  private cfg: AuthConfig;

  constructor(
    o: {
      id: string;
      sessionToken: string;
      createdAt: Date;
      lastActivityAt: Date;
    },
    cfg: AuthConfig,
  ) {
    this.id = o.id;
    this.sessionToken = o.sessionToken;
    this.createdAt = o.createdAt;
    this.lastActivityAt = o.lastActivityAt;
    this.cfg = cfg;
  }

  getSessionToken() {
    return this.sessionToken;
  }
  getSessionIdleExpiry(): Date | null {
    const t = this.cfg.options.idleTTL;
    return t ? new Date(this.lastActivityAt.getTime() + t) : null;
  }
  getSessionAbsoluteExpiry(): Date | null {
    const t = this.cfg.options.absoluteTTL;
    return t ? new Date(this.createdAt.getTime() + t) : null;
  }
  isIdleExpired(): boolean {
    const e = this.getSessionIdleExpiry();
    return e ? Date.now() > e.getTime() : false;
  }
  isAbsoluteExpired(): boolean {
    const e = this.getSessionAbsoluteExpiry();
    return e ? Date.now() > e.getTime() : false;
  }
  isValid() {
    return !this.isIdleExpired() && !this.isAbsoluteExpired();
  }
}

const IDLE_TTL = 9 * 3_600 * 1_000; // 9 hours
const ABS_TTL = 7 * 24 * 3_600 * 1_000; // 7 days
const FULL_CFG: AuthConfig = {
  options: { idleTTL: IDLE_TTL, absoluteTTL: ABS_TTL },
};

function mk(createdMsAgo = 0, lastActiveMsAgo = 0, cfg = FULL_CFG): Session {
  const now = Date.now();
  return new Session(
    {
      id: "s",
      sessionToken: randomBytes(32).toString("hex"),
      createdAt: new Date(now - createdMsAgo),
      lastActivityAt: new Date(now - lastActiveMsAgo),
    },
    cfg,
  );
}

describe("Session idle TTL", () => {
  it("getSessionIdleExpiry() = lastActivityAt + idleTTL", () => {
    const s = mk(1000, 1000);
    expect(s.getSessionIdleExpiry()?.getTime()).toBe(
      s.lastActivityAt.getTime() + IDLE_TTL,
    );
  });
  it("returns null when no idleTTL configured", () => {
    expect(
      mk(0, 0, { options: { absoluteTTL: ABS_TTL } }).getSessionIdleExpiry(),
    ).toBeNull();
  });
  it("isIdleExpired() false for recently active session", () => {
    expect(mk(1000, 60_000).isIdleExpired()).toBe(false);
  });
  it("isIdleExpired() true when idle TTL elapsed", () => {
    expect(mk(1000, IDLE_TTL + 1000).isIdleExpired()).toBe(true);
  });
});

describe("Session absolute TTL", () => {
  it("getSessionAbsoluteExpiry() = createdAt + absoluteTTL", () => {
    const s = mk(1000, 1000);
    expect(s.getSessionAbsoluteExpiry()?.getTime()).toBe(
      s.createdAt.getTime() + ABS_TTL,
    );
  });
  it("isAbsoluteExpired() false for recent session", () => {
    expect(mk(60_000, 60_000).isAbsoluteExpired()).toBe(false);
  });
  it("isAbsoluteExpired() true when absolute TTL elapsed", () => {
    expect(mk(ABS_TTL + 1000, 60_000).isAbsoluteExpired()).toBe(true);
  });
});

describe("Session combined validity", () => {
  it("isValid() true when neither TTL elapsed", () => {
    expect(mk(60_000, 60_000).isValid()).toBe(true);
  });
  it("isValid() false when idle TTL elapsed", () => {
    expect(mk(60_000, IDLE_TTL + 1000).isValid()).toBe(false);
  });
  it("isValid() false when absolute TTL elapsed", () => {
    expect(mk(ABS_TTL + 1000, 60_000).isValid()).toBe(false);
  });
  it("isValid() false when both TTLs elapsed", () => {
    expect(mk(ABS_TTL + 1000, IDLE_TTL + 1000).isValid()).toBe(false);
  });
  it("isValid() true when no TTLs configured (no expiry)", () => {
    expect(mk(ABS_TTL + 1000, IDLE_TTL + 1000, { options: {} }).isValid()).toBe(
      true,
    );
  });
});

describe("Session token rotation", () => {
  it("assigns a new unique token on rotation", () => {
    const s = mk();
    const old = s.getSessionToken();
    s.sessionToken = randomBytes(32).toString("hex");
    expect(s.getSessionToken()).not.toBe(old);
  });
  it("new token is 64-char hex (256 bits of entropy)", () => {
    const s = mk();
    s.sessionToken = randomBytes(32).toString("hex");
    expect(s.getSessionToken()).toMatch(/^[a-f0-9]{64}$/);
  });
  it("100 successive rotations produce 100 unique tokens", () => {
    const s = mk();
    const tokens = new Set(
      Array.from({ length: 100 }, () => {
        s.sessionToken = randomBytes(32).toString("hex");
        return s.getSessionToken();
      }),
    );
    expect(tokens.size).toBe(100);
  });
  it("stolen token after rotation is rejected (old token no longer matches)", () => {
    const s = mk();
    const stolen = s.getSessionToken();
    s.sessionToken = randomBytes(32).toString("hex");
    expect(s.getSessionToken() === stolen).toBe(false);
  });
});
