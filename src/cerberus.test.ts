import { describe, it, expect } from "vitest";
import { parseConfig } from "./config.js";
import { detectCi } from "./ci.js";
import { mergeSarif } from "./merge.js";
import { evaluateGate } from "./gate.js";
import { buildEnvelope, targetFromEnv } from "./upload.js";
import { buildInvocations } from "./scanners.js";
import { flattenFindings } from "./table.js";
import { buildReport, COMMENT_MARKER } from "./report.js";
import { prTargetFromEnv } from "./publish.js";
import type { UploadResponse } from "./types.js";

describe("parseConfig", () => {
  it("returns full defaults for empty/missing config", () => {
    const c = parseConfig({});
    expect(c.scanners.semgrep).toEqual({ enabled: true, config: "p/security-audit", args: [] });
    expect(c.scanners.trivy.scanners).toEqual(["vuln", "secret", "misconfig"]);
    expect(c.scanners.checkov.enabled).toBe(true);
    expect(c.scanners.hadolint.enabled).toBe(true);
    expect(c.gate.failOn).toBe("new-critical");
    expect(c.upload).toEqual({ mode: "auto", partial: false });
  });

  it("disables scanners and overrides gate/upload", () => {
    const c = parseConfig({
      scanners: { trivy: { enabled: false }, semgrep: { config: "p/ci" } },
      gate: { fail_on: "new-high" },
      upload: { mode: "report", partial: true },
    });
    expect(c.scanners.trivy.enabled).toBe(false);
    expect(c.scanners.semgrep.config).toBe("p/ci");
    expect(c.gate.failOn).toBe("new-high");
    expect(c.upload).toEqual({ mode: "report", partial: true });
  });

  it("rejects unknown gate policies and modes", () => {
    expect(() => parseConfig({ gate: { fail_on: "sometimes" } })).toThrow(/fail_on/);
    expect(() => parseConfig({ upload: { mode: "maybe" } })).toThrow(/mode/);
  });

  it("validates custom scanners", () => {
    expect(() => parseConfig({ scanners: { custom: [{ name: "x", command: "echo hi" }] } })).toThrow(/\{output\}/);
    const c = parseConfig({ scanners: { custom: [{ name: "x", command: "echo > {output}" }] } });
    expect(c.scanners.custom).toHaveLength(1);
  });
});

describe("detectCi", () => {
  it("reads GitLab env", () => {
    const ctx = detectCi("/tmp", {
      GITLAB_CI: "true",
      CI_PROJECT_NAME: "web",
      CI_COMMIT_BRANCH: "main",
      CI_DEFAULT_BRANCH: "main",
      CI_COMMIT_SHA: "abc",
      CI_COMMIT_AUTHOR: "Dev <dev@x.com>",
    });
    expect(ctx.provider).toBe("gitlab");
    expect(ctx.repo).toBe("web");
    expect(ctx.branch).toBe("main");
    expect(ctx.commit).toBe("abc");
  });

  it("reads GitHub env and prefers the PR head branch", () => {
    const ctx = detectCi("/tmp", {
      GITHUB_ACTIONS: "true",
      GITHUB_REPOSITORY: "startmatter/web",
      GITHUB_REF_NAME: "42/merge",
      GITHUB_HEAD_REF: "feature-x",
      GITHUB_SHA: "def",
    });
    expect(ctx.provider).toBe("github");
    expect(ctx.repo).toBe("web");
    expect(ctx.branch).toBe("feature-x");
  });

  it("falls back to local git", () => {
    const ctx = detectCi(process.cwd(), {});
    expect(ctx.provider).toBe("local");
    expect(ctx.repo.length).toBeGreaterThan(0);
  });
});

describe("mergeSarif", () => {
  it("concatenates runs and counts results", () => {
    const a = { runs: [{ results: [{}, {}] }] };
    const b = { runs: [{ results: [{}] }, { results: [] }] };
    const { sarif, results } = mergeSarif([a, b, null, { runs: "junk" }]);
    expect(sarif.runs).toHaveLength(3);
    expect(results).toBe(3);
    expect(sarif.version).toBe("2.1.0");
  });

  it("keeps only referenced rules and rewrites ruleIndex", () => {
    // Scanners embed their whole catalogue; only the matched rules may ship.
    const log = {
      runs: [{
        tool: { driver: { name: "semgrep", rules: [
          { id: "unused-1", help: { markdown: "x".repeat(5000) } },
          { id: "hit-a", properties: { "security-severity": "9.1" }, help: { markdown: "x".repeat(5000) } },
          { id: "unused-2" },
          { id: "hit-b", helpUri: "https://example.com/b" },
        ] } },
        results: [
          { ruleId: "hit-b", ruleIndex: 3, message: { text: "b" } },
          { ruleId: "hit-a", ruleIndex: 1, message: { text: "a" } },
          { ruleId: "hit-a", ruleIndex: 1, message: { text: "a again" } },
        ],
      }],
    };
    const { sarif } = mergeSarif([log]);
    const run = sarif.runs[0] as { tool: { driver: { rules: Array<Record<string, unknown>> } }; results: Array<Record<string, unknown>> };

    expect(run.tool.driver.rules.map((r) => r.id)).toEqual(["hit-b", "hit-a"]);
    // The severity source survives; the prose does not.
    expect(run.tool.driver.rules[1]!.properties).toEqual({ "security-severity": "9.1" });
    expect(run.tool.driver.rules[1]!.help).toBeUndefined();
    // Indices now point at the pruned array.
    expect(run.results.map((r) => r.ruleIndex)).toEqual([0, 1, 1]);
    expect(JSON.stringify(sarif)).not.toContain("xxxxx");
  });

  it("drops a ruleIndex that cannot be resolved rather than mispointing it", () => {
    const log = { runs: [{ tool: { driver: { rules: [{ id: "a" }] } }, results: [{ ruleIndex: 7, message: { text: "?" } }] }] };
    const { sarif } = mergeSarif([log]);
    const run = sarif.runs[0] as { results: Array<Record<string, unknown>> };
    expect(run.results[0]!.ruleIndex).toBeUndefined();
  });
});

describe("evaluateGate", () => {
  const response = (over: Partial<UploadResponse>): UploadResponse => ({
    ok: true,
    summary: { total: 5, new: 0, known: 5, suppressed: 0, fixed: 0, reopened: 0, tasksCreated: 0 },
    new: [],
    ...over,
  });

  it("passes when nothing is new", () => {
    expect(evaluateGate("new-critical", response({})).failed).toBe(false);
  });

  it("fails on a new critical for new-critical, but not on high", () => {
    const withHigh = response({ summary: { ...response({}).summary!, new: 1 }, new: [{ title: "t", severity: "high", file: null, line: null, taskId: null }] });
    expect(evaluateGate("new-critical", withHigh).failed).toBe(false);
    expect(evaluateGate("new-high", withHigh).failed).toBe(true);
    const withCrit = response({ summary: { ...response({}).summary!, new: 1 }, new: [{ title: "t", severity: "critical", file: "a.ts", line: 1, taskId: null }] });
    const r = evaluateGate("new-critical", withCrit);
    expect(r.failed).toBe(true);
    expect(r.reason).toContain("a.ts:1");
  });

  it("any-new trusts the summary even when the echo list is empty", () => {
    const r = evaluateGate("any-new", response({ summary: { ...response({}).summary!, new: 3 }, new: [] }));
    expect(r.failed).toBe(true);
  });

  it("never fails on baseline or with policy never", () => {
    const withCrit = response({ baseline: true, summary: { ...response({}).summary!, new: 1 }, new: [{ title: "t", severity: "critical", file: null, line: null, taskId: null }] });
    expect(evaluateGate("new-critical", withCrit).failed).toBe(false);
    expect(evaluateGate("never", withCrit).failed).toBe(false);
  });
});

describe("upload helpers", () => {
  it("builds the envelope from CI context", () => {
    const env = buildEnvelope(
      { provider: "gitlab", repo: "web", branch: "f", defaultBranch: "main", commit: "abc", author: "a@b.c", changedFiles: ["x.ts"] },
      "check", true, { runs: [] },
    );
    expect(env.meta).toMatchObject({ repo: "web", branch: "f", baselineBranch: "main", mode: "check", partial: true, changedFiles: ["x.ts"] });
  });

  it("requires both url and secret in env", () => {
    expect(targetFromEnv({})).toBeNull();
    expect(targetFromEnv({ K_SARIF_URL: "http://x" })).toBeNull();
    expect(targetFromEnv({ K_SARIF_URL: "http://x", K_SARIF_SECRET: "s" })).toMatchObject({ headerName: "X-Webhook-Secret" });
  });
});

describe("buildInvocations", () => {
  it("builds argv for the built-in heads and shell for custom", () => {
    const config = parseConfig({ scanners: { custom: [{ name: "own", command: "node check.js -o {output}" }] } });
    const inv = buildInvocations(config, "/tmp/out");
    expect(inv.map((i) => i.name)).toEqual(["semgrep", "gitleaks", "trivy", "checkov", "hadolint", "own"]);
    expect(inv[0]!.command).toContain("--sarif");
    expect(inv[5]!.command).toBe("node check.js -o /tmp/out/custom-0.sarif");
  });

  it("reads checkov's report from the name checkov itself picks", () => {
    const inv = buildInvocations(parseConfig({}), "/tmp/out").find((i) => i.name === "checkov")!;
    expect(inv.output).toBe("/tmp/out/results_sarif.sarif");
    expect(inv.command).toContain("--output-file-path");
  });

  it("keeps checkov out of the scanned directory", () => {
    // github_configuration writes `github_conf/` into the workspace as root,
    // which breaks the next checkout on a self-hosted runner.
    const inv = buildInvocations(parseConfig({}), "/tmp/out").find((i) => i.name === "checkov")!;
    const argv = inv.command as string[];
    expect(argv[argv.indexOf("--skip-framework") + 1]).toBe("github_configuration");
  });

  it("hadolint writes an empty report when the repo has no Dockerfile", () => {
    const inv = buildInvocations(parseConfig({}), "/tmp/out").find((i) => i.name === "hadolint")!;
    expect(inv.command).toContain('"version":"2.1.0"'); // the no-Dockerfile fallback
    expect(inv.command).toContain("hadolint -f sarif");
  });

  it("skips disabled scanners", () => {
    const config = parseConfig({
      scanners: { semgrep: { enabled: false }, gitleaks: { enabled: false }, checkov: { enabled: false }, hadolint: { enabled: false } },
    });
    expect(buildInvocations(config, "/tmp/out").map((i) => i.name)).toEqual(["trivy"]);
  });
});

describe("flattenFindings", () => {
  it("maps severity and sorts by rank", () => {
    const findings = flattenFindings({
      runs: [{
        tool: { driver: { name: "semgrep", rules: [{ id: "r1", properties: { "security-severity": "9.9" } }] } },
        results: [
          { ruleId: "low", level: "note", message: { text: "note" } },
          { ruleId: "r1", ruleIndex: 0, message: { text: "crit" }, locations: [{ physicalLocation: { artifactLocation: { uri: "a.ts" }, region: { startLine: 3 } } }] },
        ],
      }],
    });
    expect(findings[0]).toMatchObject({ severity: "critical", location: "a.ts:3" });
    expect(findings[1]!.severity).toBe("info");
  });
});

describe("buildReport", () => {
  const ctx = { provider: "github" as const, repo: "web", branch: "f", defaultBranch: "main", changedFiles: [] };
  const base = (over: Partial<UploadResponse>): UploadResponse => ({
    ok: true,
    summary: { total: 10, new: 0, known: 10, suppressed: 0, fixed: 0, reopened: 0, tasksCreated: 0 },
    new: [],
    ...over,
  });

  it("frames a baseline as recorded, not as work", () => {
    const md = buildReport(ctx, base({ baseline: true }), { failed: false });
    expect(md).toContain(COMMENT_MARKER);
    expect(md).toContain("baseline");
    expect(md).not.toContain("Gate failed");
  });

  it("tables the new findings with location and a link to the task", () => {
    const response = base({
      summary: { total: 12, new: 2, known: 10, suppressed: 0, fixed: 1, reopened: 0, tasksCreated: 1 },
      new: [
        { title: "SQL injection", severity: "critical", file: "src/db.ts", line: 42, taskId: "t1", taskKey: "SID/T/12", taskUrl: "https://k.example/SMK/SID/T/12" },
        { title: "Weak hash", severity: "low", file: null, line: null, taskId: null },
      ],
    });
    const md = buildReport(ctx, response, { failed: true, reason: "1 new critical finding(s)" });

    expect(md).toContain("Gate failed");
    expect(md).toContain("[SID/T/12](https://k.example/SMK/SID/T/12)");
    expect(md).toContain("`src/db.ts:42`");
    // Most severe first.
    expect(md.indexOf("SQL injection")).toBeLessThan(md.indexOf("Weak hash"));
  });

  it("says so when nothing is new", () => {
    expect(buildReport(ctx, base({}), { failed: false })).toContain("No new findings");
  });

  it("escapes a pipe so one finding cannot break the table", () => {
    const response = base({
      summary: { total: 1, new: 1, known: 0, suppressed: 0, fixed: 0, reopened: 0, tasksCreated: 0 },
      new: [{ title: "a | b", severity: "high", file: null, line: null, taskId: null }],
    });
    expect(buildReport(ctx, response, { failed: false })).toContain("a \\| b");
  });
});

describe("prTargetFromEnv", () => {
  it("recognises a pull request run", () => {
    const t = prTargetFromEnv({
      GITHUB_ACTIONS: "true", GITHUB_TOKEN: "x", GITHUB_REPOSITORY: "org/repo", GITHUB_REF: "refs/pull/42/merge",
    });
    expect(t).toMatchObject({ repo: "org/repo", prNumber: 42, api: "https://api.github.com" });
  });

  it("is null off a pull request, or without a token", () => {
    expect(prTargetFromEnv({ GITHUB_ACTIONS: "true", GITHUB_TOKEN: "x", GITHUB_REPOSITORY: "o/r", GITHUB_REF: "refs/heads/main" })).toBeNull();
    expect(prTargetFromEnv({ GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: "o/r", GITHUB_REF: "refs/pull/1/merge" })).toBeNull();
    expect(prTargetFromEnv({})).toBeNull();
  });
});
