/**
 * Express adapter — gh-aegis/express
 *
 * Drop-in middleware that scans an incoming request and blocks threats before
 * they reach your handler.
 *
 * Zero runtime dependency on Express — the import is type-only.
 *
 * @example
 * import express from "express";
 * import { aegisExpress } from "gh-aegis/express";
 * const app = express();
 * app.use(express.json());
 * app.use(aegisExpress({ scope: "input" }));
 */
import type { Request, Response, NextFunction, RequestHandler } from "express";
import { createAegisGuard } from "../aegis-guard.js";
import type { AegisOptions, ScanContext, ScanResult } from "../types.js";

export interface AegisExpressOptions extends AegisOptions {
  /** Scan scope. Default: "input". */
  scope?: ScanContext["scope"];
  /** HTTP status returned when a request is blocked. Default: 400. */
  statusCode?: number;
  /**
   * Extract the text to scan from the request.
   * Default: every string field present in the body among
   * message/input/prompt/text/content/query, joined with newlines.
   */
  getText?: (req: Request) => string | undefined;
  /** Custom block handler. Default: `res.status(statusCode).json({ ... })`. */
  onBlock?: (result: ScanResult, req: Request, res: Response) => void;
}

const DEFAULT_FIELDS = ["message", "input", "prompt", "text", "content", "query"];

function defaultGetText(req: Request): string | undefined {
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

export function aegisExpress(options: AegisExpressOptions = {}): RequestHandler {
  const guard = createAegisGuard({ enabled: true, ...options });
  const scope = options.scope ?? "input";
  const statusCode = options.statusCode ?? 400;
  const getText = options.getText ?? defaultGetText;

  return (req: Request, res: Response, next: NextFunction): void => {
    let text: string | undefined;
    try {
      text = getText(req);
    } catch {
      text = undefined;
    }
    if (typeof text !== "string" || text.length === 0) {
      next();
      return;
    }

    void guard
      .scan(text, { scope })
      .then((result) => {
        if (result.safe) {
          next();
          return;
        }
        if (options.onBlock) {
          options.onBlock(result, req, res);
          return;
        }
        res.status(statusCode).json({
          error: "Request blocked by gh-aegis",
          threatType: result.threatType,
          score: result.score,
        });
      })
      .catch(() => {
        // Fail closed: never let a request through on an internal/handler error.
        if (!res.headersSent) {
          res.status(statusCode).json({ error: "Request blocked by gh-aegis (internal error)" });
        }
      });
  };
}
