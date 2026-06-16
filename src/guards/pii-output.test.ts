/**
 * pii-output.test.ts — Coverage for the PII output guard (LLM02 / OWASP LLM Top 10)
 *
 * W6·QA run 34: pii-output.ts shipped in Aegis v0.2 with zero automated tests.
 * These 19 tests cover: happy path (clean text), all 8 PII pattern types,
 * cumulative multi-PII redaction, sanitized field semantics, and orchestrator
 * integration via AegisGuard scope routing.
 *
 * GUARDRAIL: DO NOT delete — these are the only tests for the PII guard.
 */
import { describe, test, expect } from "vitest";
import { scanPiiOutput } from "./pii-output";
import { ThreatType, createAegisGuard } from "../index";

// ── Direct guard: clean text ──────────────────────────────────────────────────

describe("scanPiiOutput — clean text", () => {
  test("returns safe=true, score=0, sanitized=input for clean text", () => {
    const input = "The recommended approach is to use dependency injection.";
    const result = scanPiiOutput(input);
    expect(result.safe).toBe(true);
    expect(result.score).toBe(0);
    expect(result.sanitized).toBe(input);
    expect(result.threatType).toBeUndefined();
  });

  test("empty string input is safe, sanitized=''", () => {
    const result = scanPiiOutput("");
    expect(result.safe).toBe(true);
    expect(result.score).toBe(0);
    expect(result.sanitized).toBe("");
  });
});

// ── Direct guard: PII pattern detection ──────────────────────────────────────

describe("scanPiiOutput — PII pattern detection (all 8 types)", () => {
  test("detects and redacts email address (score 80)", () => {
    const input = "Contact the team at alice@example.com for more info.";
    const result = scanPiiOutput(input);
    expect(result.safe).toBe(false);
    expect(result.threatType).toBe(ThreatType.PII_OUTPUT);
    expect(result.score).toBe(80);
    expect(result.sanitized).toContain("[REDACTED:email-address]");
    expect(result.sanitized).not.toContain("alice@example.com");
  });

  test("detects and redacts US phone number (score 75)", () => {
    const input = "Call us at (555) 123-4567 during business hours.";
    const result = scanPiiOutput(input);
    expect(result.safe).toBe(false);
    expect(result.threatType).toBe(ThreatType.PII_OUTPUT);
    expect(result.score).toBe(75);
    expect(result.sanitized).toContain("[REDACTED:phone-number]");
    expect(result.sanitized).not.toContain("(555)");
  });

  test("detects and redacts IBAN (score 85)", () => {
    const input = "Please transfer to IT60X0542811101000000123456.";
    const result = scanPiiOutput(input);
    expect(result.safe).toBe(false);
    expect(result.threatType).toBe(ThreatType.PII_OUTPUT);
    expect(result.score).toBe(85);
    expect(result.sanitized).toContain("[REDACTED:iban]");
    expect(result.sanitized).not.toContain("IT60");
  });

  test("detects and redacts OpenAI/Stripe API key (score 95)", () => {
    const input = "Your key is sk-abc1234567890abcdef1234567890ab.";
    const result = scanPiiOutput(input);
    expect(result.safe).toBe(false);
    expect(result.threatType).toBe(ThreatType.PII_OUTPUT);
    expect(result.score).toBe(95);
    expect(result.sanitized).toContain("[REDACTED:openai-stripe-api-key]");
    expect(result.sanitized).not.toContain("sk-abc");
  });

  test("detects and redacts GitHub personal access token (score 95)", () => {
    const input = "Export GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";
    const result = scanPiiOutput(input);
    expect(result.safe).toBe(false);
    expect(result.threatType).toBe(ThreatType.PII_OUTPUT);
    expect(result.score).toBe(95);
    expect(result.sanitized).toContain("[REDACTED:github-token]");
    expect(result.sanitized).not.toContain("ghp_");
  });

  test("detects and redacts Anthropic API key (score 95)", () => {
    const input = "API_KEY=sk-ant-api03-abcdefghij1234567890abcdefghij12345";
    const result = scanPiiOutput(input);
    expect(result.safe).toBe(false);
    expect(result.threatType).toBe(ThreatType.PII_OUTPUT);
    expect(result.score).toBe(95);
    expect(result.sanitized).toContain("[REDACTED:anthropic-api-key]");
    expect(result.sanitized).not.toContain("sk-ant-");
  });

  test("detects and redacts Italian Codice Fiscale (score 85)", () => {
    const input = "The fiscal code is RSSMRA80A01H501Z in the document.";
    const result = scanPiiOutput(input);
    expect(result.safe).toBe(false);
    expect(result.threatType).toBe(ThreatType.PII_OUTPUT);
    expect(result.score).toBe(85);
    expect(result.sanitized).toContain("[REDACTED:codice-fiscale]");
    expect(result.sanitized).not.toContain("RSSMRA80A01H501Z");
  });

  test("detects and redacts Bearer token (score 90)", () => {
    const input =
      "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdefgh12345678";
    const result = scanPiiOutput(input);
    expect(result.safe).toBe(false);
    expect(result.threatType).toBe(ThreatType.PII_OUTPUT);
    expect(result.score).toBe(90);
    expect(result.sanitized).toContain("[REDACTED:bearer-token]");
  });
});

// ── Direct guard: multi-PII and cumulative redaction ─────────────────────────

describe("scanPiiOutput — multi-PII cumulative redaction", () => {
  test("redacts ALL occurrences of the same type (global flag via toGlobal)", () => {
    const input =
      "Primary: alice@example.com — Backup: bob@example.org — Use either.";
    const result = scanPiiOutput(input);
    expect(result.safe).toBe(false);
    expect(result.sanitized).not.toContain("alice@example.com");
    expect(result.sanitized).not.toContain("bob@example.org");
    const count =
      (result.sanitized ?? "").split("[REDACTED:email-address]").length - 1;
    expect(count).toBe(2);
  });

  test("redacts multiple different PII types in the same string", () => {
    const input =
      "Contact alice@example.com or call (555) 987-6543 for assistance.";
    const result = scanPiiOutput(input);
    expect(result.safe).toBe(false);
    expect(result.sanitized).not.toContain("alice@example.com");
    expect(result.sanitized).not.toContain("987-6543");
    expect(result.sanitized).toContain("[REDACTED:email-address]");
    expect(result.sanitized).toContain("[REDACTED:phone-number]");
  });

  test("score is max across all matched patterns (email=80 + github-token=95 → 95)", () => {
    const input =
      "Email: dev@example.com — Token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1234";
    const result = scanPiiOutput(input);
    expect(result.safe).toBe(false);
    expect(result.score).toBe(95);
  });
});

// ── Direct guard: sanitized field semantics ──────────────────────────────────

describe("scanPiiOutput — sanitized field always present", () => {
  test("sanitized is defined on both safe=true and safe=false results", () => {
    const clean = "No PII here — just a helpful answer.";
    const dirty = "Reach alice@acme.com for support.";
    expect(scanPiiOutput(clean).sanitized).toBeDefined();
    expect(scanPiiOutput(dirty).sanitized).toBeDefined();
  });

  test("score on clean input is exactly 0", () => {
    expect(scanPiiOutput("Hello world").score).toBe(0);
  });
});

// ── Integration: AegisGuard orchestrator scope routing ───────────────────────

describe("AegisGuard — scope=output routes to PII guard", () => {
  // Must be explicitly enabled: a disabled guard passes everything through, so
  // these routing assertions only mean something when the guard is active.
  const aegis = createAegisGuard({ enabled: true });

  test("scope=output with email → blocked + sanitized populated", async () => {
    const result = await aegis.scan("Reply to dev@company.com ASAP.", {
      scope: "output",
    });
    expect(result.safe).toBe(false);
    expect(result.threatType).toBe(ThreatType.PII_OUTPUT);
    expect(result.sanitized).toBeDefined();
    expect(result.sanitized).not.toContain("dev@company.com");
  });

  test("scope=output with clean text → safe=true + sanitized=input", async () => {
    const input = "Here is a helpful summary of the document.";
    const result = await aegis.scan(input, { scope: "output" });
    expect(result.safe).toBe(true);
    expect(result.sanitized).toBe(input);
  });

  test("scope=input with email does NOT trigger PII guard (injection check only)", async () => {
    // Input scope → injection + jailbreak only, NOT PII — a plain user email passes
    const result = await aegis.scan(
      "My email is user@test.com, can you help?",
      { scope: "input" },
    );
    expect(result.safe).toBe(true);
    // sanitized is absent for non-output scope
    expect(result.sanitized).toBeUndefined();
  });

  test("AEGIS_ENABLED=false → disabled guard passes everything through", async () => {
    const prev = process.env.AEGIS_ENABLED;
    process.env.AEGIS_ENABLED = "false";
    const disabledAegis = createAegisGuard();
    process.env.AEGIS_ENABLED = prev;

    const result = await disabledAegis.scan(
      "sk-abc1234567890abcdef1234567890ab",
      { scope: "output" },
    );
    expect(result.safe).toBe(true);
    expect(result.score).toBe(0);
  });
});
