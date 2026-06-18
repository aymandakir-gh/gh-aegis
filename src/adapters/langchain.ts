/**
 * LangChain adapter — gh-aegis/langchain
 *
 * `aegisCallbackHandler()` returns a plain object structurally compatible with
 * LangChain's `CallbackHandlerMethods`, so you can drop it into any chain/model
 * call's `callbacks` array. It scans prompts/messages (LLM01/04/07/10) before the
 * model runs, the generated text (LLM02/04/05/06/07/08) after, and (optionally) tool
 * inputs — throwing `AegisBlockedError` on a violation.
 *
 * Zero runtime dependency on LangChain: this file imports no `@langchain/*` package
 * and defines the small structural types it needs locally, so it builds and ships
 * without LangChain installed. Whether a thrown error aborts the run depends on how
 * you attach the handler (LangChain logs callback errors unless configured to raise);
 * for hard enforcement, prefer the `gh-aegis/ai` middleware or call `scan()` directly.
 *
 * @example
 * import { aegisCallbackHandler } from "gh-aegis/langchain";
 * await chain.invoke(input, { callbacks: [aegisCallbackHandler()] });
 */
import { createAegisGuard } from "../aegis-guard.js";
import { AegisBlockedError } from "../errors.js";
import type { AegisOptions } from "../types.js";

export { AegisBlockedError };

// ─── Minimal structural types (a subset of LangChain's, defined locally) ──────

interface MessageLike {
  content?: unknown;
}
interface GenerationLike {
  text?: string;
  message?: MessageLike;
}
interface LLMResultLike {
  generations?: GenerationLike[][];
}

/** The handler shape LangChain accepts in a `callbacks` array (the subset we set). */
export interface AegisCallbackHandler {
  name: string;
  handleLLMStart(llm: unknown, prompts: string[], ...rest: unknown[]): Promise<void>;
  handleChatModelStart(
    llm: unknown,
    messages: MessageLike[][],
    ...rest: unknown[]
  ): Promise<void>;
  handleLLMEnd(output: LLMResultLike, ...rest: unknown[]): Promise<void>;
  handleToolStart(tool: unknown, input: string, ...rest: unknown[]): Promise<void>;
}

export interface AegisLangChainOptions extends AegisOptions {
  /** Scan tool inputs (output scope: dangerous commands/SSRF/secrets). Default: true. */
  scanToolInput?: boolean;
}

/**
 * Best-effort tool name from LangChain's serialized tool descriptor. LangChain
 * passes the tool's serialized form as the first arg to `handleToolStart`; the
 * name lives at `.name` (LCEL Runnables) or as the last segment of `.id` (the
 * Serializable constructor path, e.g. `["langchain", "tools", "Calculator"]`).
 */
function toolName(tool: unknown): string {
  if (typeof tool !== "object" || tool === null) return "";
  const t = tool as Record<string, unknown>;
  if (typeof t["name"] === "string") return t["name"];
  if (Array.isArray(t["id"])) {
    const last = t["id"][t["id"].length - 1];
    if (typeof last === "string") return last;
  }
  return "";
}

/** Flatten a LangChain message's content (string or array of text parts) to text. */
function messageText(message: MessageLike | undefined): string {
  const content = message?.content;
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    const parts: string[] = [];
    for (const part of content) {
      if (
        part &&
        typeof part === "object" &&
        (part as Record<string, unknown>)["type"] === "text" &&
        typeof (part as Record<string, unknown>)["text"] === "string"
      ) {
        parts.push((part as Record<string, unknown>)["text"] as string);
      }
    }
    return parts.join("\n");
  }
  return "";
}

/**
 * Build a gh-aegis LangChain callback handler. Scans on `handleLLMStart` /
 * `handleChatModelStart` (input), `handleLLMEnd` (output), and `handleToolStart`
 * (tool input, output scope) — throwing AegisBlockedError on a violation.
 */
export function aegisCallbackHandler(
  options: AegisLangChainOptions = {},
): AegisCallbackHandler {
  const guard = createAegisGuard({ enabled: true, ...options });
  const scanToolInput = options.scanToolInput ?? true;
  // Was an allowlist opted into (option > policy > env)? The tool-call-OOB guard
  // fails closed on an EMPTY list (blocks every tool), so we only gate tool names
  // when the user actually configured one — otherwise we'd break unguarded chains.
  const envAllowed =
    typeof process !== "undefined" && process.env
      ? process.env["ALLOWED_TOOLS"]
      : undefined;
  const allowlistConfigured =
    (options.allowedTools?.length ?? 0) > 0 ||
    (options.policy?.allowedTools?.length ?? 0) > 0 ||
    (envAllowed?.trim().length ?? 0) > 0;

  async function check(text: string, phase: "input" | "output"): Promise<void> {
    if (!text) return;
    const r = await guard.scan(text, { scope: phase });
    if (!r.safe) throw new AegisBlockedError(phase, r);
  }

  // Tool-scope scan of the tool NAME: enforces the allowlist (LLM08
  // tool-call-OOB) and the tool-only SSRF patterns that the output-scope content
  // scan deliberately skips. Scope "tool" is what activates both guards.
  async function checkTool(name: string): Promise<void> {
    if (!name) return;
    const r = await guard.scan(name, { scope: "tool" });
    if (!r.safe) throw new AegisBlockedError("tool", r);
  }

  return {
    name: "gh-aegis",
    async handleLLMStart(_llm, prompts) {
      for (const p of prompts ?? []) await check(String(p), "input");
    },
    async handleChatModelStart(_llm, messages) {
      for (const conversation of messages ?? []) {
        for (const m of conversation ?? []) await check(messageText(m), "input");
      }
    },
    async handleLLMEnd(output) {
      for (const generation of output?.generations ?? []) {
        for (const g of generation ?? []) {
          await check(g.text ?? messageText(g.message), "output");
        }
      }
    },
    async handleToolStart(tool, input) {
      // Enforce the tool allowlist when one is configured (an empty list fails
      // closed and would block every tool, so only gate when the user opted in).
      // The tool identity comes from LangChain's serialized descriptor; when that
      // carries no name (e.g. a bare {} in tests/custom runners) we fall back to
      // the input string, which then doubles as the tool identifier.
      if (allowlistConfigured) {
        const name = toolName(tool) || (typeof input === "string" ? input : "");
        await checkTool(name);
      }
      // Dangerous content / secrets in the tool's arguments (output scope).
      if (scanToolInput && typeof input === "string") await check(input, "output");
    },
  };
}
