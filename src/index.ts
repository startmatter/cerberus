#!/usr/bin/env node
/**
 * cerberus scan [path] — run the configured scanners, merge SARIF, and gate
 * the pipeline. Fully local: no backend, no upload, no tasks.
 *
 * Exit codes: 0 clean · 1 gate failed · 2 runtime/config error.
 */

import { parseArgs } from "node:util";
import { resolve, join } from "node:path";
import { readFileSync } from "node:fs";
import { loadConfig } from "./config.js";
import { detectCi } from "./ci.js";
import { runScanners } from "./scanners.js";
import { mergeSarif } from "./merge.js";
import { evaluateGate } from "./gate.js";
import { flattenFindings, renderTable } from "./table.js";
import { buildReport } from "./report.js";
import {
  writeJobSummary,
  prTargetFromEnv,
  upsertPrComment,
  mrTargetFromEnv,
  upsertMrNote,
} from "./publish.js";

const HELP = `cerberus — security scan orchestrator and merge gate

Usage:
  cerberus scan [path] [options]
  cerberus version

Options:
  --config <file>     Config file (default: <path>/cerberus.yml)
  --no-gate           Print findings but never fail the process (local runs skip the gate by default)
  --json              Print the merged SARIF to stdout instead of a table
  --help              Show this help
`;

function fail(message: string): never {
  console.error(`cerberus: ${message}`);
  process.exit(2);
}

async function main() {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    allowPositionals: true,
    options: {
      config: { type: "string" },
      "no-gate": { type: "boolean", default: false },
      json: { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
  });

  const command = positionals[0] ?? "scan";
  if (values.help || command === "help") {
    console.log(HELP);
    return;
  }
  if (command === "version") {
    const pkg = JSON.parse(
      readFileSync(join(import.meta.dirname, "..", "package.json"), "utf8"),
    ) as { version: string };
    console.log(pkg.version);
    return;
  }
  if (command !== "scan") fail(`unknown command "${command}" — try --help`);

  const cwd = resolve(positionals[1] ?? ".");
  const config = loadConfig(values.config ?? join(cwd, "cerberus.yml"));
  const ctx = detectCi(cwd);

  // ── Run the heads ──
  console.error(`cerberus: scanning ${ctx.repo} (${ctx.branch}) at ${cwd}`);
  const runs = await runScanners(config, cwd);
  for (const run of runs) {
    const took = `${Math.round(run.durationMs / 100) / 10}s`;
    console.error(
      run.ok
        ? `cerberus: ${run.name} done in ${took}`
        : `cerberus: ${run.name} FAILED (${run.error})`,
    );
  }
  const succeeded = runs.filter((r) => r.ok);
  if (runs.length === 0) fail("no scanners enabled");
  if (succeeded.length === 0) fail("every scanner failed");

  const { sarif, results } = mergeSarif(succeeded.map((r) => r.sarif));
  console.error(
    `cerberus: ${results} raw result(s) from ${succeeded.length} scanner(s)`,
  );

  if (values.json) {
    console.log(JSON.stringify(sarif));
    return;
  }

  const findings = flattenFindings(sarif);
  console.log(renderTable(findings, process.stdout.isTTY ?? false));

  // A release/deploy pipeline is downstream of the merge request that
  // already scanned and gated this exact commit — re-running an unscoped
  // sweep here would fail every release over pre-existing, unrelated CVEs
  // rather than anything that release changed. Still worth running for
  // visibility, just never blocking.
  const noGate =
    values["no-gate"] || ctx.provider === "local" || ctx.scope === "tag";
  if (noGate) {
    console.error(
      ctx.scope === "tag"
        ? "cerberus: gate skipped (release/tag pipeline — already gated on its merge request)"
        : "cerberus: gate skipped (local run — pass --config for CI-detected env, or this is intentional)",
    );
    return;
  }

  const gate = evaluateGate(config.gate.failOn, findings, ctx);
  console.error(
    `cerberus: ${gate.scoped.length} finding(s) in scope (${ctx.scope})` +
      (gate.failed ? " · GATE FAILED" : " · gate passed"),
  );

  // Publish before exiting: a failed gate is exactly when the reader needs the
  // detail, and process.exit() below would skip anything after it.
  const report = buildReport(ctx, gate);
  if (writeJobSummary(report))
    console.error("cerberus: report written to the job summary");
  const pr = prTargetFromEnv();
  if (pr) {
    const outcome = await upsertPrComment(pr, report);
    console.error(
      outcome === "failed"
        ? "cerberus: could not comment on the pull request (needs pull-requests: write)"
        : `cerberus: report ${outcome} on PR #${pr.prNumber}`,
    );
  }
  const mr = mrTargetFromEnv();
  if (mr) {
    const outcome = await upsertMrNote(mr, report);
    console.error(
      outcome === "failed"
        ? "cerberus: could not comment on the merge request (check CERBERUS_GITLAB_TOKEN)"
        : `cerberus: report ${outcome} on MR !${mr.mrIid}`,
    );
  }

  if (gate.failed) {
    console.error(
      `cerberus: GATE FAILED (${config.gate.failOn}): ${gate.reason}`,
    );
    process.exit(1);
  }
  console.error(`cerberus: gate passed (${config.gate.failOn})`);
}

main().catch((err) => fail((err as Error).message));
