/** Merge per-scanner SARIF logs into one 2.1.0 log (runs are concatenated —
 *  the backend normalizes and dedups per run). */

interface SarifLike {
  runs?: unknown[];
}

export function mergeSarif(logs: unknown[]): { sarif: { version: string; $schema: string; runs: unknown[] }; results: number } {
  const runs: unknown[] = [];
  let results = 0;
  for (const log of logs) {
    const l = (log ?? {}) as SarifLike;
    if (!Array.isArray(l.runs)) continue;
    for (const run of l.runs) {
      if (!run || typeof run !== "object") continue;
      runs.push(run);
      const r = (run as { results?: unknown[] }).results;
      if (Array.isArray(r)) results += r.length;
    }
  }
  return {
    sarif: {
      version: "2.1.0",
      $schema: "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
      runs,
    },
    results,
  };
}
