/** Merge per-scanner SARIF logs into one 2.1.0 log (runs are concatenated —
 *  the backend normalizes and dedups per run). */

interface SarifRule {
  id?: string;
  [key: string]: unknown;
}

interface SarifResult {
  ruleId?: string;
  ruleIndex?: number;
  [key: string]: unknown;
}

interface SarifRun {
  tool?: { driver?: { rules?: SarifRule[]; [key: string]: unknown }; [key: string]: unknown };
  results?: SarifResult[];
  [key: string]: unknown;
}

/**
 * Rule fields worth their weight: severity (`properties`), the human title
 * (`shortDescription`), the explanation (`fullDescription`) and the docs link.
 *
 * `help` is dropped — scanners repeat the whole advisory there, which is what
 * made these reports weigh tens of megabytes. `fullDescription` is a sentence
 * or two and is what a reader actually needs.
 */
const KEPT_RULE_FIELDS = [
  "id", "name", "shortDescription", "fullDescription", "helpUri", "properties", "defaultConfiguration",
];

function slimRule(rule: SarifRule): SarifRule {
  const out: SarifRule = {};
  for (const field of KEPT_RULE_FIELDS) {
    if (rule[field] !== undefined) out[field] = rule[field];
  }
  return out;
}

/**
 * Keep only the rules a run's results actually reference, and rewrite their
 * `ruleIndex` to match.
 *
 * Scanners embed their whole catalogue: a Semgrep or Checkov report carries
 * thousands of rule definitions with long help texts, so a scan with a handful
 * of findings still weighs tens of megabytes and the upload is rejected.
 */
function pruneRun(run: SarifRun): SarifRun {
  const rules = run.tool?.driver?.rules;
  if (!Array.isArray(rules) || rules.length === 0) return run;

  const results = Array.isArray(run.results) ? run.results : [];
  const kept: SarifRule[] = [];
  const newIndexById = new Map<string, number>();

  const keep = (rule: SarifRule | undefined): number | undefined => {
    if (!rule) return undefined;
    const id = typeof rule.id === "string" ? rule.id : undefined;
    if (id && newIndexById.has(id)) return newIndexById.get(id);
    const index = kept.length;
    kept.push(slimRule(rule));
    if (id) newIndexById.set(id, index);
    return index;
  };

  const newResults = results.map((result) => {
    const byIndex = typeof result.ruleIndex === "number" ? rules[result.ruleIndex] : undefined;
    const byId = typeof result.ruleId === "string" ? rules.find((r) => r?.id === result.ruleId) : undefined;
    const index = keep(byIndex ?? byId);
    // Drop a stale ruleIndex rather than let it point at the wrong rule.
    const { ruleIndex: _old, ...rest } = result;
    return index === undefined ? rest : { ...rest, ruleIndex: index };
  });

  return {
    ...run,
    tool: { ...run.tool, driver: { ...run.tool?.driver, rules: kept } },
    results: newResults,
  };
}

export function mergeSarif(logs: unknown[]): { sarif: { version: string; $schema: string; runs: unknown[] }; results: number } {
  const runs: unknown[] = [];
  let results = 0;
  for (const log of logs) {
    const l = (log ?? {}) as { runs?: unknown[] };
    if (!Array.isArray(l.runs)) continue;
    for (const runRaw of l.runs) {
      if (!runRaw || typeof runRaw !== "object") continue;
      const run = runRaw as SarifRun;
      runs.push(pruneRun(run));
      if (Array.isArray(run.results)) results += run.results.length;
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
