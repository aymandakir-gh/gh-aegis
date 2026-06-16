/**
 * gh-aegis benchmark harness.
 *
 * Runs every detector over the committed labeled dataset (datasets/*.json),
 * computes precision / recall / F1 per OWASP category, writes a JSON report and
 * a markdown table to bench/, and exits non-zero if any category falls below the
 * gates in bench/thresholds.json (so regressions fail CI).
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

interface Sample {
  id: string;
  category: string;
  scope: "input" | "output" | "tool";
  label: "malicious" | "benign";
  text: string;
}

/** Threat types that count as a correct hit for each category. */
const EXPECTED: Record<string, ThreatType[]> = {
  LLM01: [ThreatType.PROMPT_INJECTION, ThreatType.JAILBREAK],
  LLM02: [ThreatType.PII_OUTPUT],
  LLM04: [ThreatType.DATA_POISONING],
  LLM05: [ThreatType.IMPROPER_OUTPUT],
  LLM06: [ThreatType.SENSITIVE_DISCLOSURE],
  LLM07: [ThreatType.SYSTEM_PROMPT_LEAK],
  LLM08: [ThreatType.EXCESSIVE_AGENCY, ThreatType.TOOL_CALL_OOB],
  LLM10: [ThreatType.UNBOUNDED_CONSUMPTION],
};

const OWASP_NAME: Record<string, string> = {
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
interface Metrics extends Counts {
  precision: number;
  recall: number;
  f1: number;
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

async function main(): Promise<void> {
  // Load all dataset files.
  const samples: Sample[] = [];
  for (const f of readdirSync(datasetsDir)) {
    if (!f.endsWith(".json")) continue;
    const arr = JSON.parse(readFileSync(join(datasetsDir, f), "utf8")) as Sample[];
    samples.push(...arr);
  }

  const aegis = createAegisGuard({ enabled: true });

  const counts: Record<string, Counts> = {};
  for (const cat of Object.keys(EXPECTED)) {
    counts[cat] = { malicious: 0, benign: 0, tp: 0, fp: 0, fn: 0, tn: 0 };
  }

  const misclassified: Array<{
    id: string;
    category: string;
    expected: string;
    got: string;
  }> = [];

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
  const totals: Counts = {
    malicious: 0,
    benign: 0,
    tp: 0,
    fp: 0,
    fn: 0,
    tn: 0,
  };
  for (const cat of Object.keys(EXPECTED)) {
    perCategory[cat] = prf(counts[cat]);
    for (const k of Object.keys(totals) as (keyof Counts)[]) {
      totals[k] += counts[cat][k];
    }
  }
  const overall = prf(totals);
  const fpRate = totals.benign === 0 ? 0 : totals.fp / totals.benign;

  // Threshold gating (optional file).
  let thresholds: Record<
    string,
    { precision?: number; recall?: number; f1?: number }
  > = {};
  let gating = false;
  try {
    thresholds = JSON.parse(
      readFileSync(join(benchDir, "thresholds.json"), "utf8"),
    );
    gating = true;
  } catch {
    /* no thresholds file yet — report only */
  }

  const failures: string[] = [];
  if (gating) {
    for (const cat of Object.keys(EXPECTED)) {
      const t = thresholds[cat];
      const m = perCategory[cat];
      if (!t) continue;
      for (const k of ["precision", "recall", "f1"] as const) {
        const gate = t[k];
        if (gate !== undefined && m[k] + 1e-9 < gate) {
          failures.push(
            `${cat}.${k} = ${m[k].toFixed(3)} < gate ${gate.toFixed(3)}`,
          );
        }
      }
    }
  }

  // Markdown table.
  const rows = Object.keys(EXPECTED).map((cat) => {
    const m = perCategory[cat];
    return `| ${cat} | ${OWASP_NAME[cat]} | ${m.malicious} / ${m.benign} | ${pct(m.precision)} | ${pct(m.recall)} | ${m.f1.toFixed(2)} |`;
  });
  const table = [
    "| OWASP | Category | Samples (mal/ben) | Precision | Recall | F1 |",
    "|---|---|---|---|---|---|",
    ...rows,
    `| **All** | **Overall** | **${totals.malicious} / ${totals.benign}** | **${pct(overall.precision)}** | **${pct(overall.recall)}** | **${overall.f1.toFixed(2)}** |`,
  ].join("\n");

  const report = {
    generatedAt: new Date().toISOString(),
    sampleCount: samples.length,
    falsePositiveRate: fpRate,
    overall,
    perCategory,
    misclassified,
  };

  mkdirSync(benchDir, { recursive: true });
  writeFileSync(join(benchDir, "report.json"), JSON.stringify(report, null, 2) + "\n");
  writeFileSync(
    join(benchDir, "REPORT.md"),
    `# Benchmark report\n\nGenerated by \`npm run bench\` over ${samples.length} labeled samples.\nFalse-positive rate (benign flagged): **${pct(fpRate)}**.\n\n${table}\n`,
  );

  // Console output.
  console.log(`\ngh-aegis benchmark — ${samples.length} samples\n`);
  console.log(table);
  console.log(`\nFalse-positive rate: ${pct(fpRate)}`);
  if (misclassified.length) {
    console.log(`\nMisclassified (${misclassified.length}):`);
    for (const m of misclassified) {
      console.log(`  ${m.id} [${m.category}] expected=${m.expected} got=${m.got}`);
    }
  }

  if (!gating) {
    console.log(
      "\n(no bench/thresholds.json — reporting only, not gating)",
    );
  } else if (failures.length) {
    console.error(`\n✗ Threshold gate FAILED:\n  ${failures.join("\n  ")}`);
    process.exit(1);
  } else {
    console.log("\n✓ All category thresholds met.");
  }
}

main().catch((err) => {
  console.error("bench failed:", err);
  process.exit(1);
});
