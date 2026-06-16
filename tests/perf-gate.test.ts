/**
 * Latency perf-gate tests.
 *
 * Proves the perf harness produces sane stats and that the gate works in both
 * directions: it PASSES at the committed budget (the live latency clears it), and
 * it FAILS against an impossibly tight budget. Absolute timings are not asserted
 * (those live in `npm run perf`, gated in CI) — only the gate logic and the fact
 * that the real p95s are within the committed budget.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  runPerf,
  perfFailures,
  type PerfReport,
  type PerfBudget,
} from "../scripts/perf";

let report: PerfReport;
const budget: PerfBudget = JSON.parse(
  readFileSync(join(process.cwd(), "bench", "perf-budget.json"), "utf8"),
);

beforeAll(async () => {
  report = await runPerf();
}, 30_000);

describe("perf harness", () => {
  it("measures every detector and the end-to-end stages", () => {
    expect(report.detectors).toHaveLength(10);
    expect(report.endToEnd.map((s) => s.label)).toEqual([
      "scan:input",
      "scan:output",
      "inspect",
    ]);
  });

  it("produces finite, ordered percentiles", () => {
    for (const s of [...report.detectors, ...report.endToEnd]) {
      expect(Number.isFinite(s.p95)).toBe(true);
      expect(s.p50).toBeGreaterThanOrEqual(0);
      expect(s.p95).toBeGreaterThanOrEqual(s.p50);
      expect(s.p99).toBeGreaterThanOrEqual(s.p95);
      expect(s.iters).toBeGreaterThan(0);
    }
  });
});

describe("perf gate — both directions", () => {
  it("PASSES at the committed budget (zero-ML speed claim holds)", () => {
    expect(perfFailures(report, budget)).toEqual([]);
  });

  it("FAILS against an impossibly tight budget", () => {
    const tight: PerfBudget = {
      perDetectorP95Ms: 1e-9,
      scanP95Ms: 1e-9,
      inspectP95Ms: 1e-9,
    };
    const failures = perfFailures(report, tight);
    expect(failures.length).toBeGreaterThan(0);
  });
});
