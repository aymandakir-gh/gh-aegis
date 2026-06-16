/**
 * gh-aegis — public API
 *
 * @example
 * import { createAegisGuard, ThreatType } from "gh-aegis";
 *
 * const aegis = createAegisGuard({ enabled: true });
 * const result = await aegis.scan(userInput, { scope: "input" });
 * if (!result.safe) {
 *   console.error("Threat detected:", result.threatType, result.score);
 * }
 *
 * Framework adapters live under subpath exports:
 *   import { aegisExpress } from "gh-aegis/express";
 *   import { aegisFastify } from "gh-aegis/fastify";
 *   import { aegisMiddleware } from "gh-aegis/ai";
 */
export { createAegisGuard } from "./aegis-guard.js";
export { ThreatType, OWASP_LLM } from "./types.js";
export type {
  AegisGuard,
  AegisOptions,
  ScanContext,
  ScanResult,
  Finding,
  InspectReport,
} from "./types.js";
export {
  validatePolicy,
  parsePolicy,
  resolvePolicy,
  DETECTOR_IDS,
} from "./policy.js";
export type {
  AegisPolicy,
  DetectorPolicy,
  DetectorId,
  ValidationResult,
  ResolvedPolicy,
} from "./policy.js";
export { AegisBlockedError } from "./errors.js";
export { createStreamGuard, guardTextStream } from "./stream.js";
export type {
  StreamGuard,
  StreamGuardOptions,
  StreamGuardResult,
} from "./stream.js";
