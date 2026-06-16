/**
 * gh-aegis CLI — `npx gh-aegis scan <file|->`
 *
 * Scans a file (or stdin with `-`) line by line for OWASP LLM Top 10 threats and
 * exits non-zero if anything is found. Human-readable by default, `--json` for
 * machine output. Zero-ML, deterministic, offline.
 *
 * Exit codes: 0 = clean, 1 = findings, 2 = usage/IO error.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createAegisGuard } from "./aegis-guard.js";
import { parsePolicy } from "./policy.js";
import type { AegisPolicy } from "./policy.js";

function version(): string {
  try {
    const pkgPath = join(dirname(fileURLToPath(import.meta.url)), "..", "package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { version?: string };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

const HELP = `gh-aegis — deterministic, zero-ML guard for the OWASP LLM Top 10

Usage:
  gh-aegis scan <file>     Scan a file for threats
  gh-aegis scan -          Scan standard input
  npx gh-aegis scan app.log

Options:
  --json            Output findings as JSON
  --policy <file>   Load a declarative policy (detectors/scopes/thresholds/redaction)
  -h, --help        Show this help
  -v, --version     Show version

Exit codes: 0 = clean, 1 = findings detected, 2 = usage or IO error.
`;

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

interface CliFinding {
  line: number;
  threatType: string;
  owaspId: string;
  owaspName: string;
  score: number;
  detail: string;
  excerpt: string;
}

/** Run the CLI. Returns the process exit code (does not call process.exit). */
export async function run(argv: string[]): Promise<number> {
  // Extract `--policy <file>` / `--policy=<file>` before generic flag parsing.
  let policyPath: string | undefined;
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--policy") {
      policyPath = argv[++i];
      continue;
    }
    if (a.startsWith("--policy=")) {
      policyPath = a.slice("--policy=".length);
      continue;
    }
    rest.push(a);
  }

  const flags = new Set(rest.filter((a) => a.startsWith("-") && a !== "-"));
  const positionals = rest.filter((a) => !a.startsWith("-") || a === "-");

  if (flags.has("-h") || flags.has("--help")) {
    process.stdout.write(HELP);
    return 0;
  }
  if (flags.has("-v") || flags.has("--version")) {
    process.stdout.write(version() + "\n");
    return 0;
  }

  const command = positionals[0];
  if (command !== "scan") {
    process.stderr.write(
      `error: unknown or missing command${command ? ` "${command}"` : ""}. Try --help\n`,
    );
    return 2;
  }

  const target = positionals[1];
  if (!target) {
    process.stderr.write("error: scan needs a <file> argument (or - for stdin)\n");
    return 2;
  }

  let policy: AegisPolicy | undefined;
  if (policyPath !== undefined) {
    let rawPolicy: string;
    try {
      rawPolicy = readFileSync(policyPath, "utf8");
    } catch {
      process.stderr.write(`error: cannot read policy file ${policyPath}\n`);
      return 2;
    }
    try {
      policy = parsePolicy(JSON.parse(rawPolicy));
    } catch (err) {
      process.stderr.write(
        `error: invalid policy ${policyPath}: ${err instanceof Error ? err.message : String(err)}\n`,
      );
      return 2;
    }
  }

  let text: string;
  try {
    text = target === "-" ? await readStdin() : readFileSync(target, "utf8");
  } catch {
    process.stderr.write(`error: cannot read ${target === "-" ? "stdin" : target}\n`);
    return 2;
  }

  const guard = createAegisGuard({ enabled: true, policy });
  const lines = text.split(/\r?\n/);
  const findings: CliFinding[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    const report = await guard.inspect(line);
    for (const f of report.findings) {
      findings.push({
        line: i + 1,
        threatType: f.threatType,
        owaspId: f.owaspId,
        owaspName: f.owaspName,
        score: f.score,
        detail: f.detail,
        excerpt: line.trim().slice(0, 100),
      });
    }
  }

  const json = flags.has("--json");
  if (json) {
    process.stdout.write(
      JSON.stringify(
        { safe: findings.length === 0, findingCount: findings.length, findings },
        null,
        2,
      ) + "\n",
    );
  } else if (findings.length === 0) {
    process.stdout.write("✓ gh-aegis: no threats detected\n");
  } else {
    process.stdout.write(
      `✗ gh-aegis: ${findings.length} finding(s)\n`,
    );
    for (const f of findings) {
      process.stdout.write(
        `  line ${f.line}  [${f.owaspId}] ${f.threatType} (score ${f.score}) — ${f.detail}\n` +
          `    ${f.excerpt}\n`,
      );
    }
  }

  return findings.length === 0 ? 0 : 1;
}
