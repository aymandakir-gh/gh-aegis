/**
 * ToolCallOob guard — LLM08
 * Blocks tool calls that are not in the session-level allowlist.
 * Fail-closed: empty allowlist blocks everything.
 */
import type { ScanContext, ScanResult } from "../types";
import { ThreatType } from "../types";

export function scanToolCallOob(
  input: string,
  context?: ScanContext,
): ScanResult {
  const allowedTools = context?.allowedTools ?? [];
  const toolName = input.trim();

  // Fail-closed: no allowlist configured → block all tool calls
  if (allowedTools.length === 0) {
    return {
      safe: false,
      threatType: ThreatType.TOOL_CALL_OOB,
      score: 100,
      details: [
        "Tool call blocked: allowedTools list is empty. " +
          "Pass context.allowedTools to permit specific tools.",
      ],
    };
  }

  const isAllowed = allowedTools.some((tool) => tool === toolName);

  if (!isAllowed) {
    return {
      safe: false,
      threatType: ThreatType.TOOL_CALL_OOB,
      score: 100,
      details: [
        `Tool call out-of-bounds: "${toolName}" is not in the allowedTools list.`,
      ],
    };
  }

  return { safe: true, score: 0 };
}
