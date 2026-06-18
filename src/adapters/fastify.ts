/**
 * Fastify adapter — gh-aegis/fastify
 *
 * A `preHandler` hook that scans the request and blocks threats before your
 * route handler runs.
 *
 * Zero runtime dependency on Fastify — the import is type-only.
 *
 * @example
 * import Fastify from "fastify";
 * import { aegisFastify } from "gh-aegis/fastify";
 * const app = Fastify();
 * app.addHook("preHandler", aegisFastify({ scope: "input" }));
 */
import type {
  FastifyReply,
  FastifyRequest,
  preHandlerHookHandler,
} from "fastify";
import { createAegisGuard } from "../aegis-guard.js";
import type { AegisOptions, ScanContext, ScanResult } from "../types.js";

export interface AegisFastifyOptions extends AegisOptions {
  /** Scan scope. Default: "input". */
  scope?: ScanContext["scope"];
  /** HTTP status returned when a request is blocked. Default: 400. */
  statusCode?: number;
  /**
   * Extract the text to scan from the request.
   * Default: every string field present in the body among
   * message/input/prompt/text/content/query, joined with newlines.
   */
  getText?: (req: FastifyRequest) => string | undefined;
  /** Custom block handler. Default: `reply.code(statusCode).send({ ... })`. */
  onBlock?: (result: ScanResult, req: FastifyRequest, reply: FastifyReply) => void;
}

const DEFAULT_FIELDS = ["message", "input", "prompt", "text", "content", "query"];

function defaultGetText(req: FastifyRequest): string | undefined {
  const body: unknown = req.body;
  if (typeof body === "string") return body;
  if (body && typeof body === "object") {
    const record = body as Record<string, unknown>;
    // Scan EVERY known field present, not just the first match. Returning only
    // the first field let a benign `message` shadow a malicious `prompt`/
    // `content`/`query` in the same body, bypassing the guard entirely. The
    // fields are joined with newlines so a single scan covers them all.
    const parts: string[] = [];
    for (const field of DEFAULT_FIELDS) {
      const value = record[field];
      if (typeof value === "string" && value.length > 0) parts.push(value);
    }
    if (parts.length > 0) return parts.join("\n");
  }
  return undefined;
}

export function aegisFastify(
  options: AegisFastifyOptions = {},
): preHandlerHookHandler {
  const guard = createAegisGuard({ enabled: true, ...options });
  const scope = options.scope ?? "input";
  const statusCode = options.statusCode ?? 400;
  const getText = options.getText ?? defaultGetText;

  return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    let text: string | undefined;
    try {
      text = getText(req);
    } catch {
      text = undefined;
    }
    if (typeof text !== "string" || text.length === 0) return;

    const result = await guard.scan(text, { scope });
    if (result.safe) return;

    if (options.onBlock) {
      options.onBlock(result, req, reply);
      return;
    }
    await reply.code(statusCode).send({
      error: "Request blocked by gh-aegis",
      threatType: result.threatType,
      score: result.score,
    });
  };
}
