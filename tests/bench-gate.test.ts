/**
 * Benchmark threshold-gate regression tests.
 *
 * Proves the CI gate works in BOTH directions:
 *   - it PASSES at the committed thresholds (the live baseline clears them), and
 *   - it FAILS when a gate is raised above the measured baseline (a real
 *     regression would breach it).
 *
 * Also asserts dataset integrity that the bench depends on: zero false positives
 * (no benign sample is flagged) and category purity (no caught-malicious sample
 * is attributed to the wrong OWASP family). These guard against a future detector
 * change silently corrupting the benchmark.
 */
import { describe, it, expect, beforeAll } from "vitest";
import {
  loadSamples,
  evaluate,
  gateFailures,
  loadThresholds,
  EXPECTED,
  type BenchReport,
} from "../scripts/bench";

let report: BenchReport;

beforeAll(async () => {
  report = await evaluate(loadSamples());
});

describe("benchmark dataset integrity", () => {
  it("has at least 400 labeled samples", () => {
    expect(report.sampleCount).toBeGreaterThanOrEqual(400);
  });

  it("has zero false positives (no benign sample flagged)", () => {
    const fps = report.misclassified.filter((m) => m.expected === "pass");
    expect(fps).toEqual([]);
    expect(report.falsePositiveRate).toBe(0);
  });

  it("keeps 100% precision in every category", () => {
    for (const cat of Object.keys(EXPECTED)) {
      expect(report.perCategory[cat].precision).toBe(1);
    }
  });

  it("every miss is a malicious sample (an evasion/honest miss), never a benign one", () => {
    for (const m of report.misclassified) {
      expect(m.expected).toBe("flag");
      // The only acceptable "got" for a miss is a clean pass — never a
      // cross-category attribution (which would be a purity violation).
      expect(m.got).toBe("safe");
    }
  });
});

describe("threshold gate — both directions", () => {
  it("PASSES at the committed thresholds", () => {
    const thresholds = loadThresholds();
    expect(thresholds).not.toBeNull();
    const failures = gateFailures(report, thresholds!);
    expect(failures).toEqual([]);
  });

  it("FAILS when a gate is raised above the measured baseline", () => {
    // Demand 99% recall everywhere — deterministic regex cannot clear the
    // evasion tier, so the gate must report breaches.
    const impossible = Object.fromEntries(
      Object.keys(EXPECTED).map((cat) => [cat, { recall: 0.99 }]),
    );
    const failures = gateFailures(report, impossible);
    expect(failures.length).toBeGreaterThan(0);
    expect(failures.some((f) => f.includes(".recall"))).toBe(true);
  });

  it("FAILS for a single regressed category", () => {
    const t = { LLM08: { recall: 0.999 } };
    const failures = gateFailures(report, t);
    expect(failures).toHaveLength(1);
    expect(failures[0]).toContain("LLM08.recall");
  });
});
