// Types for the playground module (plain JS that runs in the browser).
import type { InspectReport } from "../src/types.js";

/** Run every detector over `text` and return the inspection report. */
export declare function analyze(text: string): Promise<InspectReport>;
