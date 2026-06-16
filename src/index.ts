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
