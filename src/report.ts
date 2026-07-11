/** Human-facing scan report: a markdown summary for the CI job page and the
 *  pull request, so a reader sees what changed without opening the raw log. */

import type { CiContext, GateResult, UploadResponse } from "./types.js";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_MARK: Record<string, string> = {
  critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "⚪",
};

/** Marker so a re-run replaces its own comment instead of stacking a new one. */
export const COMMENT_MARKER = "<!-- cerberus-scan-report -->";

function location(f: { file: string | null; line: number | null }): string {
  if (!f.file) return "—";
  return f.line != null ? `\`${f.file}:${f.line}\`` : `\`${f.file}\``;
}

function taskCell(f: { taskKey?: string | null; taskUrl?: string | null }): string {
  if (f.taskUrl && f.taskKey) return `[${f.taskKey}](${f.taskUrl})`;
  if (f.taskKey) return f.taskKey;
  return "—";
}

/**
 * The report. `mode` decides the framing: a check gates a change (these are the
 * findings *you* are adding), a report describes the default branch.
 */
export function buildReport(ctx: CiContext, response: UploadResponse, gate: GateResult): string {
  const s = response.summary;
  if (!s) return `${COMMENT_MARKER}\n### Cerberus\n\nNo scan summary returned.`;

  const lines: string[] = [COMMENT_MARKER, "### Cerberus — security scan"];

  if (response.baseline) {
    lines.push(
      "",
      `Recorded **${s.total}** findings as the baseline for \`${ctx.repo}\`. No tasks were created — from now on only *new* findings become work and can fail this pipeline.`,
    );
    return lines.join("\n");
  }

  const findings = [...(response.new ?? [])].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );

  lines.push(
    "",
    gate.failed
      ? `❌ **Gate failed** — ${gate.reason}`
      : findings.length
        ? `⚠️ **${findings.length} new finding(s)** — below the gate threshold, so this pipeline passes.`
        : "✅ **No new findings.**",
    "",
    `\`${s.new}\` new · \`${s.known}\` already known · \`${s.fixed}\` fixed · \`${s.reopened}\` reopened · \`${s.suppressed}\` suppressed`,
  );

  if (findings.length) {
    lines.push(
      "",
      "| | Severity | Finding | Location | Task |",
      "|---|---|---|---|---|",
      ...findings.map((f) => {
        const title = f.title.replace(/\|/g, "\\|").slice(0, 120);
        return `| ${SEVERITY_MARK[f.severity] ?? ""} | ${f.severity} | ${title} | ${location(f)} | ${taskCell(f)} |`;
      }),
    );
    if (s.new > findings.length) lines.push("", `…and ${s.new - findings.length} more.`);
  }

  if (s.taskFailures) {
    lines.push("", `⚠️ ${s.taskFailures} finding(s) could not be turned into tasks: ${response.taskError ?? "unknown error"}`);
  }

  lines.push(
    "",
    "<sub>Findings already on the default branch never fail this check. Close a task as *declined* to suppress its finding for good.</sub>",
  );
  return lines.join("\n");
}
