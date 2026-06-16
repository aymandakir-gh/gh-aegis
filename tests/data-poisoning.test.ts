/**
 * Data & Model Poisoning guard — LLM04 tests.
 * Invisible-Unicode / bidi-override / ASCII-smuggling detection, the stripInvisible
 * sanitizer, benign pass-through, and orchestrator routing on input + output.
 */
import { describe, it, expect } from "vitest";
import {
  scanDataPoisoning,
  stripInvisible,
  evaluatePoisoning,
} from "../src/guards/data-poisoning";
import { createAegisGuard, ThreatType } from "../src/index";

// Invisible characters, built from code points so the source stays printable.
const ZWSP = "\u200B"; // zero-width space
const ZWNJ = "\u200C"; // zero-width non-joiner
const WJ = "\u2060"; // word joiner
const BOM = "\uFEFF"; // byte-order mark / ZWNBSP
const RLO = "\u202E"; // right-to-left override (Trojan Source)
const PDI = "\u2069"; // pop directional isolate
const TAG_A = String.fromCodePoint(0xe0041); // Unicode Tags "A" (ASCII smuggling)
const TAG_SPACE = String.fromCodePoint(0xe0020);

describe("scanDataPoisoning — smuggling channels (malicious)", () => {
  it("flags a Unicode Tags-block payload (ASCII smuggling)", () => {
    const hidden = TAG_SPACE + TAG_A + TAG_A + TAG_A;
    const r = scanDataPoisoning(`Looks normal.${hidden}`);
    expect(r.safe).toBe(false);
    expect(r.threatType).toBe(ThreatType.DATA_POISONING);
    expect(r.score).toBeGreaterThanOrEqual(90);
    expect(r.details?.[0]).toContain("unicode-tag-smuggling");
  });

  it("flags a bidi-override (Trojan Source) sequence", () => {
    const r = scanDataPoisoning(`const isAdmin = ${RLO}true${PDI};`);
    expect(r.safe).toBe(false);
    expect(r.details?.[0]).toContain("bidi-override");
  });

  it("flags a zero-width char hidden inside an ASCII word", () => {
    const r = scanDataPoisoning(`pay${ZWSP}load instructions here`);
    expect(r.safe).toBe(false);
    expect(r.details?.[0]).toContain("zero-width-in-word");
  });

  it("flags a cluster of zero-width characters", () => {
    const r = scanDataPoisoning(`hi ${ZWSP}${ZWNJ}${WJ}${BOM}${ZWSP} there`);
    expect(r.safe).toBe(false);
    expect(r.details?.[0]).toContain("zero-width-cluster");
  });
});

describe("scanDataPoisoning — benign pass-through", () => {
  const benign = [
    "Plain ASCII text with no hidden characters at all.",
    "Café résumé naïve — accented Latin is fine.",
    "Arabic text مرحبا بك uses normal letters, not overrides.",
    "Emoji \u{1F468}\u200D\u{1F469}\u200D\u{1F467} families use legitimate ZWJ joiners.",
    `A document may start with a BOM (${BOM}) and that alone is fine.`,
  ];
  for (const text of benign) {
    it(`passes: "${text.slice(0, 36)}…"`, () => {
      const r = scanDataPoisoning(text);
      expect(r.safe).toBe(true);
      expect(r.score).toBe(0);
    });
  }

  it("evaluatePoisoning returns null for a single leading BOM", () => {
    expect(evaluatePoisoning(`${BOM}hello world`)).toBeNull();
  });
});

describe("stripInvisible — sanitizer", () => {
  it("removes tag, bidi, and zero-width characters", () => {
    const dirty = `a${ZWSP}b${RLO}c${TAG_A}d`;
    expect(stripInvisible(dirty)).toBe("abcd");
  });

  it("leaves clean text unchanged", () => {
    expect(stripInvisible("clean text")).toBe("clean text");
  });
});

describe("AegisGuard routing — LLM04", () => {
  const aegis = createAegisGuard({ enabled: true });

  it("flags smuggled tag chars on input scope", async () => {
    const r = await aegis.scan(
      `Translate this:${TAG_SPACE}${TAG_A}${TAG_A}${TAG_A}`,
      { scope: "input" },
    );
    expect(r.safe).toBe(false);
    expect(r.threatType).toBe(ThreatType.DATA_POISONING);
  });

  it("flags smuggled chars on output scope and strips them in sanitized", async () => {
    const r = await aegis.scan(`answer${ZWSP}word here`, { scope: "output" });
    expect(r.safe).toBe(false);
    expect(r.threatType).toBe(ThreatType.DATA_POISONING);
    expect(r.sanitized).toBe("answerword here");
  });
});
