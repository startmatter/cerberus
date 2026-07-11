#!/usr/bin/env node
/**
 * cerberus scan [path] — run the configured scanners, merge SARIF, upload to
 * the backend and gate the pipeline on the delta.
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
import { targetFromEnv, buildEnvelope, upload } from "./upload.js";
import { evaluateGate } from "./gate.js";
import { flattenFindings, renderTable } from "./table.js";

const HELP = `cerberus — security scan orchestrator and merge gate

Usage:
  cerberus scan [path] [options]
  cerberus version

Options:
  --config <file>     Config file (default: <path>/cerberus.yml)
  --mode <mode>       auto | report | check | off (overrides upload.mode)
  --upload            Force upload even outside CI
  --partial           Mark the scan as partial (skips backend auto-close)
  --json              Print the merged SARIF to stdout instead of a table
  --help              Show this help

Environment:
  K_SARIF_URL         Backend ingest URL (required to upload)
  K_SARIF_SECRET      Backend secret (required to upload)
  K_SARIF_HEADER      Secret header name (default: X-Webhook-Secret)
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
      mode: { type: "string" },
      upload: { type: "boolean", default: false },
      partial: { type: "boolean", default: false },
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
    const pkg = JSON.parse(readFileSync(join(import.meta.dirname, "..", "package.json"), "utf8")) as { version: string };
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
    console.error(run.ok ? `cerberus: ${run.name} done in ${took}` : `cerberus: ${run.name} FAILED (${run.error})`);
  }
  const succeeded = runs.filter((r) => r.ok);
  if (runs.length === 0) fail("no scanners enabled");
  if (succeeded.length === 0) fail("every scanner failed");

  const { sarif, results } = mergeSarif(succeeded.map((r) => r.sarif));
  console.error(`cerberus: ${results} raw result(s) from ${succeeded.length} scanner(s)`);

  if (values.json) {
    console.log(JSON.stringify(sarif));
    return;
  }

  // ── Resolve upload mode ──
  const modeOverride = values.mode;
  if (modeOverride && !["auto", "report", "check", "off"].includes(modeOverride)) {
    fail(`invalid --mode "${modeOverride}"`);
  }
  let mode = (modeOverride as typeof config.upload.mode) ?? config.upload.mode;
  if (mode === "auto") {
    if (ctx.provider === "local" && !values.upload) mode = "off";
    else mode = ctx.branch === ctx.defaultBranch ? "report" : "check";
  }

  if (mode === "off") {
    console.log(renderTable(flattenFindings(sarif), process.stdout.isTTY ?? false));
    console.error("cerberus: upload off — no gate (local scans are informational)");
    return;
  }

  const target = targetFromEnv();
  if (!target) fail("K_SARIF_URL and K_SARIF_SECRET are required to upload (or run with --mode off)");

  // ── Upload + gate ──
  const partial = values.partial || config.upload.partial;
  const response = await upload(target, buildEnvelope(ctx, mode, partial, sarif));
  if (!response.ok) fail(`upload failed: ${response.error ?? "unknown error"}`);

  const s = response.summary!;
  console.error(
    `cerberus: ${mode} → new ${s.new} · known ${s.known} · fixed ${s.fixed} · reopened ${s.reopened} · suppressed ${s.suppressed}` +
    (response.baseline ? " · BASELINE (no tasks, no gate)" : "") +
    (s.tasksCreated ? ` · ${s.tasksCreated} task(s) created` : ""),
  );
  for (const f of response.new ?? []) {
    console.error(`  NEW [${f.severity}] ${f.title}${f.file ? ` (${f.file}${f.line != null ? `:${f.line}` : ""})` : ""}${f.taskId ? ` → task ${f.taskId}` : ""}`);
  }

  const gate = evaluateGate(config.gate.failOn, response);
  if (gate.failed) {
    console.error(`cerberus: GATE FAILED (${config.gate.failOn}): ${gate.reason}`);
    process.exit(1);
  }
  console.error(`cerberus: gate passed (${config.gate.failOn})`);
}

main().catch((err) => fail((err as Error).message));
