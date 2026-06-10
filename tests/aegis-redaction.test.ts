/**
 * Aegis v0.2 — PII redaction test suite (8 tests)
 * Verifies ScanResult.sanitized: correct redaction labels, multi-PII,
 * no-PII pass-through, scope=input exclusion, empty string, truncation order.
 */
import { describe, it, expect } from "vitest";
import { createAegisGuard } from "../src/index";

describe("Aegis v0.2 — PII redaction (ScanResult.sanitized)", () => {
  const aegis = createAegisGuard({ enabled: true });

  // ─── 1. Email redaction ───────────────────────────────────────────────────

  it("email redact — replaces email with [REDACTED:email-address]", async () => {
    const result = await aegis.scan(
      "Contact: alice@example.com for details.",
      { scope: "output" },
    );
    expect(result.safe).toBe(false);
    expect(result.sanitized).toBe(
      "Contact: [REDACTED:email-address] for details.",
    );
    expect(result.sanitized).not.toContain("alice@example.com");
  });

  // ─── 2. Phone redaction ───────────────────────────────────────────────────

  it("phone redact — replaces phone number with [REDACTED:phone-number]", async () => {
    const result = await aegis.scan(
      "Call us at +1 (555) 123-4567 anytime.",
      { scope: "output" },
    );
    expect(result.safe).toBe(false);
    expect(result.sanitized).toContain("[REDACTED:phone-number]");
    expect(result.sanitized).not.toContain("123-4567");
  });

  // ─── 3. API key redaction ─────────────────────────────────────────────────

  it("API key redact — replaces sk- key with [REDACTED:openai-stripe-api-key]", async () => {
    const result = await aegis.scan(
      "Your key is sk-abcdefghijklmnopqrstu1234567890.",
      { scope: "output" },
    );
    expect(result.safe).toBe(false);
    expect(result.sanitized).toContain("[REDACTED:openai-stripe-api-key]");
    expect(result.sanitized).not.toContain("sk-abc");
  });

  // ─── 4. Multi-PII — both email and API key redacted ──────────────────────

  it("multi-PII — email and API key both redacted in sanitized", async () => {
    const result = await aegis.scan(
      "Email user@test.com with key sk-mykey12345678901234567890abcdef.",
      { scope: "output" },
    );
    expect(result.safe).toBe(false);
    expect(result.sanitized).toContain("[REDACTED:email-address]");
    expect(result.sanitized).toContain("[REDACTED:openai-stripe-api-key]");
    expect(result.sanitized).not.toContain("user@test.com");
    expect(result.sanitized).not.toContain("sk-my");
  });

  // ─── 5. No PII — sanitized equals original input ─────────────────────────

  it("no-PII — sanitized equals original input unchanged", async () => {
    const clean =
      "Q1 growth was 23% MoM. Focus on activation funnel next sprint.";
    const result = await aegis.scan(clean, { scope: "output" });
    expect(result.safe).toBe(true);
    expect(result.sanitized).toBe(clean);
  });

  // ─── 6. scope=input — sanitized not set ──────────────────────────────────

  it("scope=input — sanitized is undefined (PII guard does not run for input scope)", async () => {
    const result = await aegis.scan(
      "My email is hello@example.com",
      { scope: "input" }, // injection+jailbreak guards, not PII guard
    );
    // email present but input scope never runs PII detection
    expect(result.sanitized).toBeUndefined();
  });

  // ─── 7. Empty string ─────────────────────────────────────────────────────

  it("empty string — safe=true, sanitized is empty string", async () => {
    const result = await aegis.scan("", { scope: "output" });
    expect(result.safe).toBe(true);
    expect(result.sanitized).toBe("");
  });

  // ─── 8. Truncation before redaction ──────────────────────────────────────

  it("truncation-before-redact — PII beyond maxInputLength is never seen", async () => {
    // maxInputLength=20; email starts at index 21+
    const aegisShort = createAegisGuard({ enabled: true, maxInputLength: 20 });
    // "Hello world! Today: " is exactly 20 chars, email follows
    const input = "Hello world! Today: user@example.com";
    const result = await aegisShort.scan(input, { scope: "output" });
    // Truncated text has no email — safe, sanitized = truncated slice
    expect(result.safe).toBe(true);
    expect(result.sanitized).toBe("Hello world! Today: ");
    expect(result.sanitized).not.toContain("@");
  });
});
