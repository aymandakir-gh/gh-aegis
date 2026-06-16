/**
 * gh-aegis benchmark harness.
 *
 * Runs every detector over the committed labeled dataset (datasets/*.json),
 * computes precision / recall / F1 per OWASP category, writes a JSON report and
 * a markdown table to bench/, and exits non-zero if any category falls below the
 * gates in bench/thresholds.json (so regressions fail CI).
 *
 * The evaluation core is exported (loadSamples / evaluate) so the threshold gate
 * can be unit-tested in both directions (passes at the real gates, fails when a
 * gate is raised above the measured baseline).
 *
 * Zero-ML, deterministic, offline. Run with: npm run bench
 */
import { readdirSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createAegisGuard, ThreatType } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const datasetsDir = join(root, "datasets");
const benchDir = join(root, "bench");

export interface Sample {
  id: string;
  category: string;
  scope: "input" | "output" | "tool";
  label: "malicious" | "benign";
  text: string;
}

/** Threat types that count as a correct hit for each category. */
export const EXPECTED: Record<string, ThreatType[]> = {
  LLM01: [ThreatType.PROMPT_INJECTION, ThreatType.JAILBREAK],
  LLM02: [ThreatType.PII_OUTPUT],
  LLM04: [ThreatType.DATA_POISONING],
  LLM05: [ThreatType.IMPROPER_OUTPUT],
  LLM06: [ThreatType.SENSITIVE_DISCLOSURE],
  LLM07: [ThreatType.SYSTEM_PROMPT_LEAK],
  LLM08: [ThreatType.EXCESSIVE_AGENCY, ThreatType.TOOL_CALL_OOB],
  LLM10: [ThreatType.UNBOUNDED_CONSUMPTION],
};

export const OWASP_NAME: Record<string, string> = {
  LLM01: "Prompt Injection",
  LLM02: "Insecure Output / PII",
  LLM04: "Data & Model Poisoning",
  LLM05: "Improper Output Handling",
  LLM06: "Sensitive Disclosure",
  LLM07: "System Prompt Leakage",
  LLM08: "Excessive Agency",
  LLM10: "Unbounded Consumption",
};

interface Counts {
  malicious: number;
  benign: number;
  tp: number;
  fp: number;
  fn: number;
  tn: number;
}
export interface Metrics extends Counts {
  precision: number;
  recall: number;
  f1: number;
}

export type Threshold = { precision?: number; recall?: number; f1?: number };

export interface BenchReport {
  generatedAt: string;
  sampleCount: number;
  falsePositiveRate: number;
  overall: Metrics;
  perCategory: Record<string, Metrics>;
  misclassified: Array<{ id: string; category: string; expected: string; got: string }>;
}

function prf(c: Counts): Metrics {
  const precision = c.tp + c.fp === 0 ? 1 : c.tp / (c.tp + c.fp);
  const recall = c.tp + c.fn === 0 ? 1 : c.tp / (c.tp + c.fn);
  const f1 =
    precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return { ...c, precision, recall, f1 };
}

function pct(n: number): string {
  return (n * 100).toFixed(1) + "%";
}

/** Load every labeled sample from datasets/*.json. */
export function loadSamples(dir: string = datasetsDir): Sample[] {
  const samples: Sample[] = [];
  for (const f of readdirSync(dir)) {
    if (!f.endsWith(".json")) continue;
    const arr = JSON.parse(readFileSync(join(dir, f), "utf8")) as Sample[];
    samples.push(...arr);
  }
  return samples;
}

/** Run every detector over the samples and compute per-category + overall metrics. */
export async function evaluate(
  samples: Sample[],
  generatedAt = "",
): Promise<BenchReport> {
  const aegis = createAegisGuard({ enabled: true });

  const counts: Record<string, Counts> = {};
  for (const cat of Object.keys(EXPECTED)) {
    counts[cat] = { malicious: 0, benign: 0, tp: 0, fp: 0, fn: 0, tn: 0 };
  }

  const misclassified: BenchReport["misclassified"] = [];

  for (const s of samples) {
    const c = counts[s.category];
    if (!c) continue;
    const res = await aegis.scan(s.text, { scope: s.scope });
    const flagged = !res.safe;
    const expected = EXPECTED[s.category] ?? [];
    const correct =
      flagged && res.threatType !== undefined && expected.includes(res.threatType);

    if (s.label === "malicious") {
      c.malicious++;
      if (correct) {
        c.tp++;
      } else {
        c.fn++;
        misclassified.push({
          id: s.id,
          category: s.category,
          expected: "flag",
          got: res.threatType ?? "safe",
        });
      }
    } else {
      c.benign++;
      if (flagged) {
        c.fp++;
        misclassified.push({
          id: s.id,
          category: s.category,
          expected: "pass",
          got: res.threatType ?? "flagged",
        });
      } else {
        c.tn++;
      }
    }
  }

  const perCategory: Record<string, Metrics> = {};
  const totals: Counts = { malicious: 0, benign: 0, tp: 0, fp: 0, fn: 0, tn: 0 };
  for (const cat of Object.keys(EXPECTED)) {
    perCategory[cat] = prf(counts[cat]);
    for (const k of Object.keys(totals) as (keyof Counts)[]) {
      totals[k] += counts[cat][k];
    }
  }
  const overall = prf(totals);
  const falsePositiveRate = totals.benign === 0 ? 0 : totals.fp / totals.benign;

  return {
    generatedAt,
    sampleCount: samples.length,
    falsePositiveRate,
    overall,
    perCategory,
    misclassified,
  };
}

/** Compare a report against per-category gates; returns the list of breaches. */
export function gateFailures(
  report: BenchReport,
  thresholds: Record<string, Threshold>,
): string[] {
  const failures: string[] = [];
  for (const cat of Object.keys(EXPECTED)) {
    const t = thresholds[cat];
    const m = report.perCategory[cat];
    if (!t || !m) continue;
    for (const k of ["precision", "recall", "f1"] as const) {
      const gate = t[k];
      if (gate !== undefined && m[k] + 1e-9 < gate) {
        failures.push(`${cat}.${k} = ${m[k].toFixed(3)} < gate ${gate.toFixed(3)}`);
      }
    }
  }
  return failures;
}

export function loadThresholds(): Record<string, Threshold> | null {
  try {
    return JSON.parse(readFileSync(join(benchDir, "thresholds.json"), "utf8"));
  } catch {
    return null;
  }
}

function markdownTable(report: BenchReport): string {
  const rows = Object.keys(EXPECTED).map((cat) => {
    const m = report.perCategory[cat];
    return `| ${cat} | ${OWASP_NAME[cat]} | ${m.malicious} / ${m.benign} | ${pct(m.precision)} | ${pct(m.recall)} | ${m.f1.toFixed(2)} |`;
  });
  const o = report.overall;
  return [
    "| OWASP | Category | Samples (mal/ben) | Precision | Recall | F1 |",
    "|---|---|---|---|---|---|",
    ...rows,
    `| **All** | **Overall** | **${o.malicious} / ${o.benign}** | **${pct(o.precision)}** | **${pct(o.recall)}** | **${o.f1.toFixed(2)}** |`,
  ].join("\n");
}

async function main(): Promise<void> {
  const samples = loadSamples();
  const report = await evaluate(samples, new Date().toISOString());
  const table = markdownTable(report);

  mkdirSync(benchDir, { recursive: true });
  writeFileSync(join(benchDir, "report.json"), JSON.stringify(report, null, 2) + "\n");
  writeFileSync(
    join(benchDir, "REPORT.md"),
    `# Benchmark report\n\nGenerated by \`npm run bench\` over ${samples.length} labeled samples.\nFalse-positive rate (benign flagged): **${pct(report.falsePositiveRate)}**.\n\n${table}\n`,
  );

  console.log(`\ngh-aegis benchmark — ${samples.length} samples\n`);
  console.log(table);
  console.log(`\nFalse-positive rate: ${pct(report.falsePositiveRate)}`);
  if (report.misclassified.length) {
    console.log(`\nMisclassified (${report.misclassified.length}):`);
    for (const m of report.misclassified) {
      console.log(`  ${m.id} [${m.category}] expected=${m.expected} got=${m.got}`);
    }
  }

  const thresholds = loadThresholds();
  if (!thresholds) {
    console.log("\n(no bench/thresholds.json — reporting only, not gating)");
    return;
  }
  const failures = gateFailures(report, thresholds);
  if (failures.length) {
    console.error(`\n✗ Threshold gate FAILED:\n  ${failures.join("\n  ")}`);
    process.exit(1);
  }
  console.log("\n✓ All category thresholds met.");
}

// Only run main() when executed directly (not when imported by a test).
const isDirectRun =
  process.argv[1] !== undefined &&
  fileURLToPath(import.meta.url) === process.argv[1];
if (isDirectRun) {
  main().catch((err) => {
    console.error("bench failed:", err);
    process.exit(1);
  });
}
