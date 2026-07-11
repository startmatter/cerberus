/** The merge gate: fail the pipeline only on NEW findings, by policy. */

import type { GatePolicy, UploadResponse } from "./types.js";

export interface GateResult {
  failed: boolean;
  reason?: string;
}

const FAIL_SEVERITIES: Record<Exclude<GatePolicy, "never">, Set<string>> = {
  "new-critical": new Set(["critical"]),
  "new-high": new Set(["critical", "high"]),
  "any-new": new Set(["critical", "high", "medium", "low", "info"]),
};

export function evaluateGate(policy: GatePolicy, response: UploadResponse): GateResult {
  if (policy === "never") return { failed: false };
  if (!response.ok || !response.summary) {
    // No verdict from the backend — do not invent one. Upload errors are
    // surfaced separately via the exit code for runtime failures.
    return { failed: false };
  }
  if (response.baseline) return { failed: false }; // first scan never gates

  const failOn = FAIL_SEVERITIES[policy];
  const offenders = (response.new ?? []).filter((f) => failOn.has(f.severity));

  // `new` echoes at most a page of findings; trust the summary for any-new.
  if (policy === "any-new" && response.summary.new > 0) {
    return { failed: true, reason: `${response.summary.new} new finding(s)` };
  }
  if (offenders.length > 0) {
    const worst = offenders[0]!;
    return {
      failed: true,
      reason: `${offenders.length} new ${[...failOn].join("/")} finding(s), e.g. "${worst.title}"${worst.file ? ` (${worst.file}${worst.line != null ? `:${worst.line}` : ""})` : ""}`,
    };
  }
  return { failed: false };
}
