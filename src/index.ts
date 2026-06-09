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
 */
export { createAegisGuard } from "./aegis-guard";
export { ThreatType } from "./types";
export type { AegisGuard, AegisOptions, ScanContext, ScanResult } from "./types";
