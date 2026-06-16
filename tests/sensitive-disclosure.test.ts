/**
 * Sensitive Disclosure guard — LLM06 tests.
 * Secrets/credentials/private-keys/system-prompt leakage, detection + redaction,
 * benign pass-through, and orchestrator routing on scope=output.
 */
import { describe, it, expect } from "vitest";
import { scanSensitiveDisclosure } from "../src/guards/sensitive-disclosure";
import { createAegisGuard, ThreatType } from "../src/index";

describe("scanSensitiveDisclosure — direct", () => {
  it("detects + redacts a PEM private key block", () => {
    const r = scanSensitiveDisclosure(
      "Here it is:\n-----BEGIN RSA PRIVATE KEY-----\nMIIB...",
    );
    expect(r.safe).toBe(false);
    expect(r.threatType).toBe(ThreatType.SENSITIVE_DISCLOSURE);
    expect(r.sanitized).toContain("[REDACTED:private-key]");
  });

  it("detects an AWS access key id", () => {
    const r = scanSensitiveDisclosure("key=AKIAIOSFODNN7EXAMPLE");
    expect(r.safe).toBe(false);
    expect(r.sanitized).toContain("[REDACTED:aws-access-key]");
    expect(r.sanitized).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("detects a Google API key", () => {
    const key = "AIza" + "B".repeat(35);
    const r = scanSensitiveDisclosure(`api: ${key}`);
    expect(r.safe).toBe(false);
    expect(r.sanitized).toContain("[REDACTED:google-api-key]");
  });

  it("detects a Slack token", () => {
    const r = scanSensitiveDisclosure("token xoxb-2401-2402-AbCdEf123456 leaked");
    expect(r.safe).toBe(false);
    expect(r.sanitized).toContain("[REDACTED:slack-token]");
  });

  it("detects a credentialed connection string", () => {
    const r = scanSensitiveDisclosure(
      "DB=postgres://admin:s3cr3tpw@db.internal:5432/app",
    );
    expect(r.safe).toBe(false);
    expect(r.sanitized).toContain("[REDACTED:connection-string-credentials]");
  });

  it("detects a generic credential assignment", () => {
    const r = scanSensitiveDisclosure('password: "hunter2secret"');
    expect(r.safe).toBe(false);
    expect(r.sanitized).toContain("[REDACTED:credential-assignment]");
  });

  it("no longer claims system-prompt leakage (moved to LLM07)", () => {
    // System-prompt content is not a secret/credential; it belongs to LLM07.
    const r = scanSensitiveDisclosure(
      "Sure — my system prompt is: You are AcmeBot, be concise.",
    );
    expect(r.safe).toBe(true);
    expect(r.score).toBe(0);
  });

  it("no longer claims a system persona echo (moved to LLM07)", () => {
    const r = scanSensitiveDisclosure(
      "You are a helpful coding assistant developed by Acme Corp.",
    );
    expect(r.safe).toBe(true);
    expect(r.score).toBe(0);
  });

  it("passes benign technical text (no secrets)", () => {
    const clean =
      "Our credential rotation policy runs monthly; see the deployment guide.";
    const r = scanSensitiveDisclosure(clean);
    expect(r.safe).toBe(true);
    expect(r.score).toBe(0);
    expect(r.sanitized).toBe(clean);
  });
});

describe("AegisGuard — scope=output routes to sensitive-disclosure", () => {
  const aegis = createAegisGuard({ enabled: true });

  it("flags a leaked private key in output and returns sanitized", async () => {
    const r = await aegis.scan(
      "-----BEGIN OPENSSH PRIVATE KEY-----\nabc...",
      { scope: "output" },
    );
    expect(r.safe).toBe(false);
    expect(r.threatType).toBe(ThreatType.SENSITIVE_DISCLOSURE);
    expect(r.sanitized).toContain("[REDACTED:private-key]");
  });
});
