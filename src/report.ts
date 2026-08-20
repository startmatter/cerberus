/** Human-facing scan report: a markdown summary for the CI job page and the
 *  pull request / merge request, so a reader sees what changed without
 *  opening the raw log. */

import type { CiContext, GateResult } from "./types.js";
import { findingLocation } from "./table.js";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_MARK: Record<string, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "⚪",
};
const MAX_ROWS = 50;

/** Marker so a re-run replaces its own comment instead of stacking a new one. */
export const COMMENT_MARKER = "<!-- cerberus-scan-report -->";

/**
 * The report. On a merge request `gate.scoped` is only the findings in files
 * the change touches; everywhere else it's everything the scan found.
 */
export function buildReport(ctx: CiContext, gate: GateResult): string {
  const findings = [...gate.scoped].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );

  const lines: string[] = [COMMENT_MARKER, "### Cerberus — security scan"];

  lines.push(
    "",
    gate.failed
      ? `❌ **Gate failed** — ${gate.reason}`
      : findings.length
        ? `⚠️ **${findings.length} finding(s) in scope** — below the gate threshold, so this pipeline passes.`
        : "✅ **No findings in scope.**",
  );

  if (findings.length) {
    lines.push(
      "",
      "| | Severity | Finding | Location |",
      "|---|---|---|---|",
      ...findings.slice(0, MAX_ROWS).map((f) => {
        const title = f.title.replace(/\|/g, "\\|").slice(0, 120);
        const loc = findingLocation(f);
        return `| ${SEVERITY_MARK[f.severity] ?? ""} | ${f.severity} | ${title} | ${loc === "-" ? "—" : `\`${loc}\``} |`;
      }),
    );
    if (findings.length > MAX_ROWS)
      lines.push("", `…and ${findings.length - MAX_ROWS} more.`);
  }

  lines.push(
    "",
    ctx.scope === "merge_request"
      ? "<sub>Only findings in files this change touches can fail this check. A pre-existing backlog elsewhere never blocks a merge.</sub>"
      : "<sub>This run gates on every qualifying finding, not just ones a specific change introduced.</sub>",
  );
  return lines.join("\n");
}
