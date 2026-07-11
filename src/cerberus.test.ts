import { describe, it, expect } from "vitest";
import { parseConfig } from "./config.js";
import { detectCi } from "./ci.js";
import { mergeSarif } from "./merge.js";
import { evaluateGate } from "./gate.js";
import { buildEnvelope, targetFromEnv } from "./upload.js";
import { buildInvocations } from "./scanners.js";
import { flattenFindings } from "./table.js";
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
