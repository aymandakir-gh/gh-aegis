/**
 * Streaming-output guard — gh-aegis
 *
 * Guards a token/chunk stream as it is produced. A violation can straddle chunk
 * boundaries (e.g. `<scr` + `ipt>`), so the guard scans a sliding window of the
 * accumulated output on every push rather than each chunk in isolation. Once any
 * detector trips, the guard latches `blocked` so later (clean) chunks stay blocked.
 *
 * The window (default 8192 chars) bounds per-push cost to O(window) — any realistic
 * attack pattern is far shorter than the window, and the guard scans on every push,
 * so a pattern completing in a chunk is always within the window at that moment.
 *
 * Framework-agnostic and zero-dependency. Compose it with any async iterable of
 * strings via `guardTextStream`, or drive it manually with `createStreamGuard`.
 */
import { createAegisGuard } from "./aegis-guard.js";
import { AegisBlockedError } from "./errors.js";
import type { AegisOptions, ScanResult } from "./types.js";

export interface StreamGuardOptions extends AegisOptions {
  /** Scan scope for each chunk. Default: "output" (the model is producing text). */
  scope?: "input" | "output";
  /** Sliding-window size (chars) scanned on each push. Default: 8192. */
  window?: number;
}

export interface StreamGuardResult {
  /** true = safe to emit so far (and never previously blocked). */
  safe: boolean;
  /** Sticky: a violation has been detected at some point in the stream. */
  blocked: boolean;
  /** Latest scan of the accumulated window. */
  result: ScanResult;
}

export interface StreamGuard {
  /** Append a chunk and re-scan the accumulated window. */
  push(chunk: string): Promise<StreamGuardResult>;
  /** Final verdict (re-scans the current window); call once the stream ends. */
  end(): Promise<StreamGuardResult>;
  /** The full accumulated output so far. */
  buffer(): string;
}

const SAFE: ScanResult = { safe: true, score: 0 };

/** Create a stateful streaming guard you push chunks into. */
export function createStreamGuard(options: StreamGuardOptions = {}): StreamGuard {
  const guard = createAegisGuard({ enabled: true, ...options });
  const scope = options.scope ?? "output";
  const window = options.window ?? 8192;

  let buf = "";
  let blocked = false;
  let last: ScanResult = SAFE;

  async function rescan(): Promise<StreamGuardResult> {
    const slice = buf.length > window ? buf.slice(buf.length - window) : buf;
    last = await guard.scan(slice, { scope });
    if (!last.safe) blocked = true;
    return { safe: !blocked, blocked, result: last };
  }

  return {
    async push(chunk: string): Promise<StreamGuardResult> {
      buf += chunk;
      return rescan();
    },
    async end(): Promise<StreamGuardResult> {
      if (buf.length === 0) return { safe: !blocked, blocked, result: last };
      return rescan();
    },
    buffer: () => buf,
  };
}

/**
 * Wrap an async iterable of text chunks, yielding each chunk while the accumulated
 * output stays safe and throwing `AegisBlockedError` the moment a detector trips
 * (before the offending chunk is yielded).
 *
 * @example
 * for await (const chunk of guardTextStream(model.textStream)) process.stdout.write(chunk);
 */
export async function* guardTextStream(
  source: AsyncIterable<string>,
  options: StreamGuardOptions = {},
): AsyncGenerator<string, void, unknown> {
  const sg = createStreamGuard(options);
  const phase = options.scope === "input" ? "input" : "output";
  for await (const chunk of source) {
    const r = await sg.push(chunk);
    if (r.blocked) throw new AegisBlockedError(phase, r.result);
    yield chunk;
  }
}
