/**
 * Vercel AI SDK adapter — gh-aegis/ai
 *
 * `aegisMiddleware()` is a `LanguageModelMiddleware` you pass to `wrapLanguageModel`.
 * It scans the prompt (LLM01/LLM10) before the model runs and the generated text
 * (LLM02/LLM06/LLM08) after, throwing `AegisBlockedError` on a violation.
 *
 * Zero runtime dependency on the AI SDK — the import is type-only.
 *
 * @example
 * import { wrapLanguageModel } from "ai";
 * import { aegisMiddleware } from "gh-aegis/ai";
 * const model = wrapLanguageModel({ model: openai("gpt-4o"), middleware: aegisMiddleware() });
 */
import type { LanguageModelMiddleware } from "ai";
import { createAegisGuard } from "../aegis-guard.js";
import type { AegisOptions } from "../types.js";
import { AegisBlockedError } from "../errors.js";

// Re-exported for backward compatibility (now lives in ../errors.ts, shared with
// the LangChain and streaming guards).
export { AegisBlockedError };

export type AegisAiOptions = AegisOptions;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

/** Collect text from an AI SDK prompt (array of messages with text parts). */
function promptToText(prompt: unknown): string {
  if (typeof prompt === "string") return prompt;
  if (!Array.isArray(prompt)) return "";
  const out: string[] = [];
  for (const msg of prompt) {
    if (!isRecord(msg)) continue;
    const content = msg["content"];
    if (typeof content === "string") {
      out.push(content);
    } else if (Array.isArray(content)) {
      for (const part of content) {
        if (
          isRecord(part) &&
          part["type"] === "text" &&
          typeof part["text"] === "string"
        ) {
          out.push(part["text"]);
        }
      }
    }
  }
  return out.join("\n");
}

/** Collect generated text from a doGenerate result (content text parts or .text). */
function resultToText(result: unknown): string {
  if (isRecord(result) && typeof result["text"] === "string") {
    return result["text"];
  }
  if (isRecord(result) && Array.isArray(result["content"])) {
    const out: string[] = [];
    for (const part of result["content"]) {
      if (
        isRecord(part) &&
        part["type"] === "text" &&
        typeof part["text"] === "string"
      ) {
        out.push(part["text"]);
      }
    }
    return out.join("\n");
  }
  return "";
}

/**
 * Build a gh-aegis middleware for the Vercel AI SDK. Enabled by default; pass
 * `{ enabled: false }` (or any AegisOptions) to configure.
 */
export function aegisMiddleware(
  options: AegisAiOptions = {},
): LanguageModelMiddleware {
  const guard = createAegisGuard({ enabled: true, ...options });

  return {
    specificationVersion: "v3",
    transformParams: async ({ params }) => {
      const text = promptToText(params.prompt);
      if (text) {
        const result = await guard.scan(text, { scope: "input" });
        if (!result.safe) throw new AegisBlockedError("input", result);
      }
      return params;
    },
    wrapGenerate: async ({ doGenerate }) => {
      const result = await doGenerate();
      const text = resultToText(result);
      if (text) {
        const scan = await guard.scan(text, { scope: "output" });
        if (!scan.safe) throw new AegisBlockedError("output", scan);
      }
      return result;
    },
  };
}
