/** The merge gate: fail on qualifying findings, scoped to the change on a
 *  merge request — everywhere else (default-branch pushes, scheduled
 *  sweeps, local runs) every finding counts. There is no backend anymore,
 *  so "new" in a policy name means "in scope for this run," not "not seen
 *  by a tracker before." */

import type {
  CiContext,
  FlatFinding,
  GatePolicy,
  GateResult,
} from "./types.js";

export type { GateResult };

const FAIL_SEVERITIES: Record<Exclude<GatePolicy, "never">, Set<string>> = {
  "new-critical": new Set(["critical"]),
  "new-high": new Set(["critical", "high"]),
  "any-new": new Set(["critical", "high", "medium", "low", "info"]),
};

function normalize(path: string): string {
  return path.replace(/^\.\//, "");
}

function scopeFindings(findings: FlatFinding[], ctx: CiContext): FlatFinding[] {
  if (ctx.scope !== "merge_request") return findings;
  const changed = new Set(ctx.changedFiles.map(normalize));
  return findings.filter((f) => f.file && changed.has(normalize(f.file)));
}

export function evaluateGate(
  policy: GatePolicy,
  findings: FlatFinding[],
  ctx: CiContext,
): GateResult {
  const scoped = scopeFindings(findings, ctx);
  if (policy === "never") return { failed: false, scoped };

  const failOn = FAIL_SEVERITIES[policy];
  const offenders = scoped.filter((f) => failOn.has(f.severity));
  if (offenders.length === 0) return { failed: false, scoped };

  const worst = offenders[0]!; // flattenFindings already sorts by severity rank
  const where = worst.file
    ? ` (${worst.file}${worst.line != null ? `:${worst.line}` : ""})`
    : "";
  return {
    failed: true,
    reason: `${offenders.length} ${[...failOn].join("/")} finding(s), e.g. "${worst.title}"${where}`,
    scoped,
  };
}
