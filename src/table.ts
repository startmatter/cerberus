/** Local findings table: flatten merged SARIF and print by severity. */

const RESET = "\x1b[0m";
const COLORS: Record<string, string> = {
  critical: "\x1b[1;31m", // bold red
  high: "\x1b[31m",
  medium: "\x1b[33m",
  low: "\x1b[36m",
  info: "\x1b[90m",
};
const RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export interface FlatFinding {
  severity: string;
  tool: string;
  ruleId: string;
  title: string;
  location: string;
}

interface Rule {
  id?: string;
  properties?: Record<string, unknown>;
  defaultConfiguration?: { level?: string };
  shortDescription?: { text?: string };
}

function severityOf(result: Record<string, unknown>, rule?: Rule): string {
  for (const props of [result.properties as Record<string, unknown> | undefined, rule?.properties]) {
    const v = props?.["security-severity"];
    const n = typeof v === "number" ? v : typeof v === "string" ? Number.parseFloat(v) : NaN;
    if (Number.isFinite(n)) {
      if (n >= 9) return "critical";
      if (n >= 7) return "high";
      if (n >= 4) return "medium";
      return n > 0 ? "low" : "info";
    }
  }
  const level = (result.level as string | undefined) ?? rule?.defaultConfiguration?.level ?? "warning";
  return level === "error" ? "high" : level === "warning" ? "medium" : "info";
}

export function flattenFindings(sarif: unknown): FlatFinding[] {
  const runs = ((sarif ?? {}) as { runs?: unknown[] }).runs;
  const out: FlatFinding[] = [];
  for (const runRaw of Array.isArray(runs) ? runs : []) {
    const run = runRaw as { tool?: { driver?: { name?: string; rules?: Rule[] } }; results?: unknown[] };
    const tool = run.tool?.driver?.name ?? "unknown";
    const rules = Array.isArray(run.tool?.driver?.rules) ? run.tool.driver.rules : [];
    const ruleById = new Map(rules.filter((r) => r?.id).map((r) => [r.id!, r]));
    for (const resRaw of Array.isArray(run.results) ? run.results : []) {
      if (!resRaw || typeof resRaw !== "object") continue;
      const result = resRaw as Record<string, unknown>;
      const ruleId = (result.ruleId as string | undefined) ?? "unknown";
      const rule =
        (typeof result.ruleIndex === "number" ? rules[result.ruleIndex] : undefined) ?? ruleById.get(ruleId);
      const loc = (result.locations as Array<{ physicalLocation?: { artifactLocation?: { uri?: string }; region?: { startLine?: number } } }> | undefined)?.[0]?.physicalLocation;
      const file = loc?.artifactLocation?.uri;
      const line = loc?.region?.startLine;
      const message = ((result.message as { text?: string } | undefined)?.text ?? "").split("\n")[0]!.trim();
      out.push({
        severity: severityOf(result, rule),
        tool,
        ruleId,
        title: message || rule?.shortDescription?.text || ruleId,
        location: file ? `${file}${line != null ? `:${line}` : ""}` : "-",
      });
    }
  }
  return out.sort((a, b) => (RANK[b.severity] ?? -1) - (RANK[a.severity] ?? -1));
}

export function renderTable(findings: FlatFinding[], useColor: boolean): string {
  if (findings.length === 0) return "No findings.";
  const lines: string[] = [];
  for (const f of findings) {
    const sev = f.severity.toUpperCase().padEnd(8);
    const colored = useColor ? `${COLORS[f.severity] ?? ""}${sev}${RESET}` : sev;
    lines.push(`${colored}  ${f.tool.padEnd(10).slice(0, 10)}  ${f.location}  ${f.title.slice(0, 100)}`);
  }
  const counts = new Map<string, number>();
  for (const f of findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  const summary = [...counts.entries()].map(([s, n]) => `${n} ${s}`).join(", ");
  lines.push("", `${findings.length} finding(s): ${summary}`);
  return lines.join("\n");
}
