/** Scanner invocations: each writes SARIF to a temp file; failures are
 *  per-scanner (one broken head must not silence the others). */

import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CerberusConfig, ScannerRun } from "./types.js";

const SCANNER_TIMEOUT_MS = 15 * 60 * 1000;

interface Invocation {
  name: string;
  /** argv form; `shell` switches to sh -c (custom scanners only). */
  command: string[] | string;
  output: string;
}

export function buildInvocations(config: CerberusConfig, outDir: string): Invocation[] {
  const inv: Invocation[] = [];
  const s = config.scanners;

  if (s.semgrep.enabled) {
    inv.push({
      name: "semgrep",
      output: join(outDir, "semgrep.sarif"),
      command: [
        "semgrep", "scan", "--config", s.semgrep.config,
        "--sarif", "--output", join(outDir, "semgrep.sarif"),
        "--metrics=off", "--quiet", ...s.semgrep.args,
      ],
    });
  }
  if (s.gitleaks.enabled) {
    inv.push({
      name: "gitleaks",
      output: join(outDir, "gitleaks.sarif"),
      command: [
        "gitleaks", "detect", "--source", ".",
        "--report-format", "sarif", "--report-path", join(outDir, "gitleaks.sarif"),
        "--exit-code", "0", "--no-banner", ...s.gitleaks.args,
      ],
    });
  }
  if (s.trivy.enabled) {
    inv.push({
      name: "trivy",
      output: join(outDir, "trivy.sarif"),
      command: [
        "trivy", "fs", "--scanners", s.trivy.scanners.join(","),
        "--format", "sarif", "--output", join(outDir, "trivy.sarif"),
        "--quiet", ...s.trivy.args, ".",
      ],
    });
  }
  if (s.checkov.enabled) {
    // --output-file-path takes a directory; checkov names the file itself.
    // It also exits non-zero when it finds anything, which is not a failure —
    // the runner prefers the report over the exit code.
    //
    // github_configuration is skipped on purpose: with a GITHUB_TOKEN in the
    // environment it calls the API and dumps `github_conf/` into the scanned
    // directory. We run as root over a mounted workspace, so that directory
    // outlives the container owned by root — and the next `actions/checkout`,
    // running as the runner's user, cannot delete it and fails the whole
    // pipeline. It audits branch protection, which we do not act on anyway.
    inv.push({
      name: "checkov",
      output: join(outDir, "results_sarif.sarif"),
      command: [
        "checkov", "-d", ".", "-o", "sarif", "--output-file-path", outDir,
        "--skip-framework", "github_configuration",
        "--compact", "--quiet", ...s.checkov.args,
      ],
    });
  }
  if (s.hadolint.enabled) {
    // hadolint takes files, not a directory, and writes to stdout. A repo with
    // no Dockerfile must still produce a valid (empty) report, not a failure.
    const output = join(outDir, "hadolint.sarif");
    const extra = s.hadolint.args.join(" ");
    inv.push({
      name: "hadolint",
      output,
      command:
        `files=$(find . -type f \\( -iname 'Dockerfile' -o -iname 'Dockerfile.*' -o -iname '*.Dockerfile' \\) ` +
        `-not -path './node_modules/*' -not -path './.git/*'); ` +
        `if [ -z "$files" ]; then printf '{"version":"2.1.0","runs":[]}' > ${output}; ` +
        `else hadolint -f sarif ${extra} $files > ${output} || true; fi`,
    });
  }
  for (const [i, custom] of s.custom.entries()) {
    const output = join(outDir, `custom-${i}.sarif`);
    inv.push({ name: custom.name, output, command: custom.command.replaceAll("{output}", output) });
  }
  return inv;
}

function run(inv: Invocation, cwd: string): Promise<{ code: number | null; error?: string }> {
  return new Promise((resolve) => {
    const child = Array.isArray(inv.command)
      ? spawn(inv.command[0]!, inv.command.slice(1), { cwd, stdio: ["ignore", "ignore", "pipe"], timeout: SCANNER_TIMEOUT_MS })
      : spawn(inv.command, { cwd, shell: true, stdio: ["ignore", "ignore", "pipe"], timeout: SCANNER_TIMEOUT_MS });
    let stderr = "";
    child.stderr?.on("data", (d: Buffer) => { if (stderr.length < 4000) stderr += d.toString(); });
    child.on("error", (err) => resolve({ code: null, error: err.message }));
    child.on("close", (code) => resolve({ code, error: code === 0 ? undefined : stderr.trim().slice(0, 500) || undefined }));
  });
}

/** Run all configured scanners sequentially (they are CPU-heavy and some are
 *  not parallel-safe on one working tree). */
export async function runScanners(config: CerberusConfig, cwd: string): Promise<ScannerRun[]> {
  const outDir = mkdtempSync(join(tmpdir(), "cerberus-"));
  const results: ScannerRun[] = [];
  try {
    for (const inv of buildInvocations(config, outDir)) {
      const started = Date.now();
      const { code, error } = await run(inv, cwd);
      const durationMs = Date.now() - started;

      let sarif: unknown;
      try {
        sarif = JSON.parse(readFileSync(inv.output, "utf8"));
      } catch {
        sarif = undefined;
      }

      // Some scanners exit non-zero yet still write a valid report — prefer the report.
      if (sarif !== undefined) {
        results.push({ name: inv.name, ok: true, sarif, durationMs });
      } else {
        results.push({
          name: inv.name,
          ok: false,
          error: error ?? (code === null ? "failed to start (is it installed?)" : `exit ${code}, no report`),
          durationMs,
        });
      }
    }
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
  return results;
}
