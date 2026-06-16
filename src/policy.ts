/**
 * Declarative policy / config for gh-aegis.
 *
 * A policy is a plain JSON object that turns detectors on/off, restricts which
 * scopes are scanned, raises per-detector score thresholds, toggles redaction, and
 * sets the LLM10 limits and the tool allowlist. It is validated by a hand-rolled,
 * zero-dependency validator (no zod/ajv) and resolved into a fast runtime the
 * orchestrator consults on every scan.
 *
 * A policy is purely subtractive on top of a fail-closed default: an unknown or
 * malformed policy is rejected loudly rather than silently weakening the guard.
 */

// ─── Detector ids (the policy keys) ───────────────────────────────────────────

export const DETECTOR_IDS = [
  "unbounded-consumption",
  "prompt-injection",
  "jailbreak",
  "system-prompt-leak",
  "data-poisoning",
  "pii",
  "sensitive-disclosure",
  "improper-output",
  "excessive-agency",
  "tool-call-oob",
] as const;

export type DetectorId = (typeof DETECTOR_IDS)[number];

const DETECTOR_SET = new Set<string>(DETECTOR_IDS);
const SCOPES = ["input", "output", "tool"] as const;

// ─── Policy shape ─────────────────────────────────────────────────────────────

export interface DetectorPolicy {
  /** Run this detector. Default: true. */
  enabled?: boolean;
  /** Only block when the detector's score is at least this (0–100). Default: 0 (use the detector's own threshold). */
  minScore?: number;
}

export interface AegisPolicy {
  /** Optional schema version marker (informational). */
  version?: number;
  /** Master on/off; mirrors AegisOptions.enabled. */
  enabled?: boolean;
  verbose?: boolean;
  /** Which scopes are scanned. A disabled scope passes everything through. */
  scopes?: { input?: boolean; output?: boolean; tool?: boolean };
  /** Per-detector toggle / threshold. A bare boolean is shorthand for { enabled }. */
  detectors?: Partial<Record<DetectorId, boolean | DetectorPolicy>>;
  /** Produce a redacted `sanitized` copy for output scope. Default: true. */
  redaction?: boolean;
  /** LLM10 / truncation limits. */
  limits?: {
    maxInputLength?: number;
    maxLength?: number;
    maxCharRun?: number;
    maxTokenRepeat?: number;
  };
  /** Default tool allowlist (scope="tool"). */
  allowedTools?: string[];
}

// ─── Validation (zero-dep) ────────────────────────────────────────────────────

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  policy: AegisPolicy;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function checkBool(v: unknown, path: string, errors: string[]): void {
  if (v !== undefined && typeof v !== "boolean") {
    errors.push(`${path} must be a boolean`);
  }
}

function checkNumber(
  v: unknown,
  path: string,
  errors: string[],
  opts: { min?: number; max?: number; integer?: boolean } = {},
): void {
  if (v === undefined) return;
  if (typeof v !== "number" || !Number.isFinite(v)) {
    errors.push(`${path} must be a finite number`);
    return;
  }
  if (opts.integer && !Number.isInteger(v)) errors.push(`${path} must be an integer`);
  if (opts.min !== undefined && v < opts.min) errors.push(`${path} must be >= ${opts.min}`);
  if (opts.max !== undefined && v > opts.max) errors.push(`${path} must be <= ${opts.max}`);
}

function checkNoUnknownKeys(
  obj: Record<string, unknown>,
  allowed: readonly string[],
  path: string,
  errors: string[],
): void {
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) {
      errors.push(`${path} has unknown key "${k}" (allowed: ${allowed.join(", ")})`);
    }
  }
}

/**
 * Validate an untrusted value as an AegisPolicy. Never throws; returns the list
 * of errors and the (best-effort) parsed policy. `valid` is true only when the
 * input is a clean, fully-recognized policy.
 */
export function validatePolicy(raw: unknown): ValidationResult {
  const errors: string[] = [];
  if (!isObject(raw)) {
    return { valid: false, errors: ["policy must be a JSON object"], policy: {} };
  }

  checkNoUnknownKeys(
    raw,
    ["version", "enabled", "verbose", "scopes", "detectors", "redaction", "limits", "allowedTools"],
    "policy",
    errors,
  );

  checkNumber(raw["version"], "policy.version", errors, { integer: true, min: 0 });
  checkBool(raw["enabled"], "policy.enabled", errors);
  checkBool(raw["verbose"], "policy.verbose", errors);
  checkBool(raw["redaction"], "policy.redaction", errors);

  if (raw["scopes"] !== undefined) {
    if (!isObject(raw["scopes"])) {
      errors.push("policy.scopes must be an object");
    } else {
      checkNoUnknownKeys(raw["scopes"], SCOPES, "policy.scopes", errors);
      for (const s of SCOPES) checkBool(raw["scopes"][s], `policy.scopes.${s}`, errors);
    }
  }

  if (raw["detectors"] !== undefined) {
    if (!isObject(raw["detectors"])) {
      errors.push("policy.detectors must be an object");
    } else {
      for (const [id, val] of Object.entries(raw["detectors"])) {
        if (!DETECTOR_SET.has(id)) {
          errors.push(`policy.detectors has unknown detector "${id}" (allowed: ${DETECTOR_IDS.join(", ")})`);
          continue;
        }
        if (typeof val === "boolean") continue;
        if (!isObject(val)) {
          errors.push(`policy.detectors.${id} must be a boolean or an object`);
          continue;
        }
        checkNoUnknownKeys(val, ["enabled", "minScore"], `policy.detectors.${id}`, errors);
        checkBool(val["enabled"], `policy.detectors.${id}.enabled`, errors);
        checkNumber(val["minScore"], `policy.detectors.${id}.minScore`, errors, { min: 0, max: 100 });
      }
    }
  }

  if (raw["limits"] !== undefined) {
    if (!isObject(raw["limits"])) {
      errors.push("policy.limits must be an object");
    } else {
      const limitKeys = ["maxInputLength", "maxLength", "maxCharRun", "maxTokenRepeat"];
      checkNoUnknownKeys(raw["limits"], limitKeys, "policy.limits", errors);
      for (const k of limitKeys) {
        checkNumber(raw["limits"][k], `policy.limits.${k}`, errors, { min: 1, integer: true });
      }
    }
  }

  if (raw["allowedTools"] !== undefined) {
    if (!Array.isArray(raw["allowedTools"]) || raw["allowedTools"].some((t) => typeof t !== "string")) {
      errors.push("policy.allowedTools must be an array of strings");
    }
  }

  return { valid: errors.length === 0, errors, policy: errors.length === 0 ? (raw as AegisPolicy) : {} };
}

/** Validate or throw. Use when loading a policy from disk — misconfig should be loud. */
export function parsePolicy(raw: unknown): AegisPolicy {
  const { valid, errors, policy } = validatePolicy(raw);
  if (!valid) {
    throw new Error(`Invalid gh-aegis policy:\n  - ${errors.join("\n  - ")}`);
  }
  return policy;
}

// ─── Resolved runtime ─────────────────────────────────────────────────────────

export interface ResolvedPolicy {
  redaction: boolean;
  scopeActive(scope: "input" | "output" | "tool"): boolean;
  detectorEnabled(id: DetectorId): boolean;
  detectorMinScore(id: DetectorId): number;
}

/** Resolve a (possibly undefined) policy into a fast runtime with safe defaults. */
export function resolvePolicy(policy?: AegisPolicy): ResolvedPolicy {
  const scopes = policy?.scopes;
  const detectors = policy?.detectors;
  return {
    redaction: policy?.redaction ?? true,
    scopeActive: (scope) => scopes?.[scope] ?? true,
    detectorEnabled: (id) => {
      const d = detectors?.[id];
      if (d === undefined) return true;
      if (typeof d === "boolean") return d;
      return d.enabled ?? true;
    },
    detectorMinScore: (id) => {
      const d = detectors?.[id];
      if (d === undefined || typeof d === "boolean") return 0;
      return d.minScore ?? 0;
    },
  };
}
