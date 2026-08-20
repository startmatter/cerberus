import { describe, it, expect } from "vitest";
import { parseConfig } from "./config.js";
import { detectCi } from "./ci.js";
import { mergeSarif } from "./merge.js";
import { evaluateGate } from "./gate.js";
import { buildInvocations } from "./scanners.js";
import { flattenFindings } from "./table.js";
import { buildReport, COMMENT_MARKER } from "./report.js";
import { prTargetFromEnv, mrTargetFromEnv } from "./publish.js";
import type { CiContext, FlatFinding } from "./types.js";

describe("parseConfig", () => {
  it("returns full defaults for empty/missing config", () => {
    const c = parseConfig({});
    expect(c.scanners.semgrep).toEqual({
      enabled: true,
      config: "p/security-audit",
      args: [],
    });
    expect(c.scanners.trivy.scanners).toEqual(["vuln", "secret", "misconfig"]);
    expect(c.scanners.checkov.enabled).toBe(true);
    expect(c.scanners.hadolint.enabled).toBe(true);
    expect(c.gate.failOn).toBe("new-critical");
  });

  it("disables scanners and overrides gate", () => {
    const c = parseConfig({
      scanners: { trivy: { enabled: false }, semgrep: { config: "p/ci" } },
      gate: { fail_on: "new-high" },
    });
    expect(c.scanners.trivy.enabled).toBe(false);
    expect(c.scanners.semgrep.config).toBe("p/ci");
    expect(c.gate.failOn).toBe("new-high");
  });

  it("rejects an unknown gate policy", () => {
    expect(() => parseConfig({ gate: { fail_on: "sometimes" } })).toThrow(
      /fail_on/,
    );
  });

  it("validates custom scanners", () => {
    expect(() =>
      parseConfig({
        scanners: { custom: [{ name: "x", command: "echo hi" }] },
      }),
    ).toThrow(/\{output\}/);
    const c = parseConfig({
      scanners: { custom: [{ name: "x", command: "echo > {output}" }] },
    });
    expect(c.scanners.custom).toHaveLength(1);
  });
});

describe("detectCi", () => {
  it("reads GitLab env on a default-branch push", () => {
    const ctx = detectCi("/tmp", {
      GITLAB_CI: "true",
      CI_PROJECT_NAME: "web",
      CI_COMMIT_BRANCH: "main",
      CI_DEFAULT_BRANCH: "main",
      CI_COMMIT_SHA: "abc",
      CI_COMMIT_AUTHOR: "Dev <dev@x.com>",
    });
    expect(ctx.provider).toBe("gitlab");
    expect(ctx.scope).toBe("default_branch");
    expect(ctx.repo).toBe("web");
    expect(ctx.branch).toBe("main");
    expect(ctx.commit).toBe("abc");
  });

  it("scopes a GitLab merge-request pipeline", () => {
    const ctx = detectCi("/tmp", {
      GITLAB_CI: "true",
      CI_PIPELINE_SOURCE: "merge_request_event",
      CI_PROJECT_NAME: "web",
    });
    expect(ctx.scope).toBe("merge_request");
  });

  it("scopes a GitLab scheduled pipeline", () => {
    const ctx = detectCi("/tmp", {
      GITLAB_CI: "true",
      CI_PIPELINE_SOURCE: "schedule",
      CI_PROJECT_NAME: "web",
    });
    expect(ctx.scope).toBe("schedule");
  });

  it("reads GitHub env and prefers the PR head branch", () => {
    const ctx = detectCi("/tmp", {
      GITHUB_ACTIONS: "true",
      GITHUB_REPOSITORY: "startmatter/web",
      GITHUB_REF_NAME: "42/merge",
      GITHUB_HEAD_REF: "feature-x",
      GITHUB_EVENT_NAME: "pull_request",
      GITHUB_SHA: "def",
    });
    expect(ctx.provider).toBe("github");
    expect(ctx.repo).toBe("web");
    expect(ctx.branch).toBe("feature-x");
    expect(ctx.scope).toBe("merge_request");
  });

  it("scopes a GitHub schedule run outside a PR", () => {
    const ctx = detectCi("/tmp", {
      GITHUB_ACTIONS: "true",
      GITHUB_REPOSITORY: "startmatter/web",
      GITHUB_EVENT_NAME: "schedule",
    });
    expect(ctx.scope).toBe("schedule");
  });

  it("falls back to local git", () => {
    const ctx = detectCi(process.cwd(), {});
    expect(ctx.provider).toBe("local");
    expect(ctx.scope).toBe("local");
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
      runs: [
        {
          tool: {
            driver: {
              name: "semgrep",
              rules: [
                { id: "unused-1", help: { markdown: "x".repeat(5000) } },
                {
                  id: "hit-a",
                  properties: { "security-severity": "9.1" },
                  help: { markdown: "x".repeat(5000) },
                },
                { id: "unused-2" },
                { id: "hit-b", helpUri: "https://example.com/b" },
              ],
            },
          },
          results: [
            { ruleId: "hit-b", ruleIndex: 3, message: { text: "b" } },
            { ruleId: "hit-a", ruleIndex: 1, message: { text: "a" } },
            { ruleId: "hit-a", ruleIndex: 1, message: { text: "a again" } },
          ],
        },
      ],
    };
    const { sarif } = mergeSarif([log]);
    const run = sarif.runs[0] as {
      tool: { driver: { rules: Array<Record<string, unknown>> } };
      results: Array<Record<string, unknown>>;
    };

    expect(run.tool.driver.rules.map((r) => r.id)).toEqual(["hit-b", "hit-a"]);
    // The severity source survives; the prose does not.
    expect(run.tool.driver.rules[1]!.properties).toEqual({
      "security-severity": "9.1",
    });
    expect(run.tool.driver.rules[1]!.help).toBeUndefined();
    // Indices now point at the pruned array.
    expect(run.results.map((r) => r.ruleIndex)).toEqual([0, 1, 1]);
    expect(JSON.stringify(sarif)).not.toContain("xxxxx");
  });

  it("drops a ruleIndex that cannot be resolved rather than mispointing it", () => {
    const log = {
      runs: [
        {
          tool: { driver: { rules: [{ id: "a" }] } },
          results: [{ ruleIndex: 7, message: { text: "?" } }],
        },
      ],
    };
    const { sarif } = mergeSarif([log]);
    const run = sarif.runs[0] as { results: Array<Record<string, unknown>> };
    expect(run.results[0]!.ruleIndex).toBeUndefined();
  });
});

describe("evaluateGate", () => {
  const ctx = (over: Partial<CiContext>): CiContext => ({
    provider: "gitlab",
    scope: "default_branch",
    repo: "web",
    branch: "main",
    defaultBranch: "main",
    changedFiles: [],
    ...over,
  });
  const finding = (over: Partial<FlatFinding>): FlatFinding => ({
    severity: "high",
    tool: "semgrep",
    ruleId: "r1",
    title: "t",
    file: null,
    line: null,
    ...over,
  });

  it("passes when there are no findings", () => {
    expect(evaluateGate("new-critical", [], ctx({})).failed).toBe(false);
  });

  it("fails on a critical for new-critical, but not on high", () => {
    const high = [finding({ severity: "high" })];
    expect(evaluateGate("new-critical", high, ctx({})).failed).toBe(false);
    expect(evaluateGate("new-high", high, ctx({})).failed).toBe(true);

    const crit = [finding({ severity: "critical", file: "a.ts", line: 1 })];
    const r = evaluateGate("new-critical", crit, ctx({}));
    expect(r.failed).toBe(true);
    expect(r.reason).toContain("a.ts:1");
  });

  it("any-new fails on any severity", () => {
    const r = evaluateGate("any-new", [finding({ severity: "info" })], ctx({}));
    expect(r.failed).toBe(true);
  });

  it("never fails with policy never, but still reports the scoped set", () => {
    const crit = [finding({ severity: "critical" })];
    const r = evaluateGate("never", crit, ctx({}));
    expect(r.failed).toBe(false);
    expect(r.scoped).toHaveLength(1);
  });

  it("on a merge request, only findings in changed files count", () => {
    const findings = [
      finding({ severity: "critical", file: "touched.ts" }),
      finding({ severity: "critical", file: "untouched.ts" }),
    ];
    const mrCtx = ctx({ scope: "merge_request", changedFiles: ["touched.ts"] });
    const r = evaluateGate("new-critical", findings, mrCtx);
    expect(r.failed).toBe(true);
    expect(r.scoped).toHaveLength(1);
    expect(r.scoped[0]!.file).toBe("touched.ts");
  });

  it("outside a merge request, every finding counts regardless of changed files", () => {
    const findings = [finding({ severity: "critical", file: "untouched.ts" })];
    const r = evaluateGate(
      "new-critical",
      findings,
      ctx({ scope: "schedule", changedFiles: [] }),
    );
    expect(r.failed).toBe(true);
    expect(r.scoped).toHaveLength(1);
  });
});

describe("buildInvocations", () => {
  it("builds argv for the built-in heads and shell for custom", () => {
    const config = parseConfig({
      scanners: {
        custom: [{ name: "own", command: "node check.js -o {output}" }],
      },
    });
    const inv = buildInvocations(config, "/tmp/out");
    expect(inv.map((i) => i.name)).toEqual([
      "semgrep",
      "gitleaks",
      "trivy",
      "checkov",
      "hadolint",
      "own",
    ]);
    expect(inv[0]!.command).toContain("--sarif");
    expect(inv[5]!.command).toBe("node check.js -o /tmp/out/custom-0.sarif");
  });

  it("reads checkov's report from the name checkov itself picks", () => {
    const inv = buildInvocations(parseConfig({}), "/tmp/out").find(
      (i) => i.name === "checkov",
    )!;
    expect(inv.output).toBe("/tmp/out/results_sarif.sarif");
    expect(inv.command).toContain("--output-file-path");
  });

  it("keeps checkov out of the scanned directory", () => {
    // github_configuration writes `github_conf/` into the workspace as root,
    // which breaks the next checkout on a self-hosted runner.
    const inv = buildInvocations(parseConfig({}), "/tmp/out").find(
      (i) => i.name === "checkov",
    )!;
    const argv = inv.command as string[];
    expect(argv[argv.indexOf("--skip-framework") + 1]).toBe(
      "github_configuration",
    );
  });

  it("hadolint writes an empty report when the repo has no Dockerfile", () => {
    const inv = buildInvocations(parseConfig({}), "/tmp/out").find(
      (i) => i.name === "hadolint",
    )!;
    expect(inv.command).toContain('"version":"2.1.0"'); // the no-Dockerfile fallback
    expect(inv.command).toContain("hadolint -f sarif");
  });

  it("skips disabled scanners", () => {
    const config = parseConfig({
      scanners: {
        semgrep: { enabled: false },
        gitleaks: { enabled: false },
        checkov: { enabled: false },
        hadolint: { enabled: false },
      },
    });
    expect(buildInvocations(config, "/tmp/out").map((i) => i.name)).toEqual([
      "trivy",
    ]);
  });
});

describe("flattenFindings", () => {
  it("maps severity, splits file/line, and sorts by rank", () => {
    const findings = flattenFindings({
      runs: [
        {
          tool: {
            driver: {
              name: "semgrep",
              rules: [{ id: "r1", properties: { "security-severity": "9.9" } }],
            },
          },
          results: [
            { ruleId: "low", level: "note", message: { text: "note" } },
            {
              ruleId: "r1",
              ruleIndex: 0,
              message: { text: "crit" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "a.ts" },
                    region: { startLine: 3 },
                  },
                },
              ],
            },
          ],
        },
      ],
    });
    expect(findings[0]).toMatchObject({
      severity: "critical",
      file: "a.ts",
      line: 3,
    });
    expect(findings[1]!.severity).toBe("info");
    expect(findings[1]!.file).toBeNull();
  });
});

describe("buildReport", () => {
  const ctx = (over: Partial<CiContext>): CiContext => ({
    provider: "github",
    scope: "merge_request",
    repo: "web",
    branch: "f",
    defaultBranch: "main",
    changedFiles: [],
    ...over,
  });

  it("says so when nothing is in scope", () => {
    const md = buildReport(ctx({}), { failed: false, scoped: [] });
    expect(md).toContain(COMMENT_MARKER);
    expect(md).toContain("No findings in scope");
  });

  it("tables findings by severity with location", () => {
    const md = buildReport(ctx({}), {
      failed: true,
      reason: '1 critical finding(s), e.g. "SQL injection" (src/db.ts:42)',
      scoped: [
        {
          severity: "critical",
          tool: "semgrep",
          ruleId: "r1",
          title: "SQL injection",
          file: "src/db.ts",
          line: 42,
        },
        {
          severity: "low",
          tool: "gitleaks",
          ruleId: "r2",
          title: "Weak hash",
          file: null,
          line: null,
        },
      ],
    });

    expect(md).toContain("Gate failed");
    expect(md).toContain("`src/db.ts:42`");
    // Most severe first.
    expect(md.indexOf("SQL injection")).toBeLessThan(md.indexOf("Weak hash"));
  });

  it("frames a below-threshold scan as passing", () => {
    const md = buildReport(ctx({}), {
      failed: false,
      scoped: [
        {
          severity: "low",
          tool: "trivy",
          ruleId: "r1",
          title: "t",
          file: null,
          line: null,
        },
      ],
    });
    expect(md).not.toContain("Gate failed");
    expect(md).toContain("below the gate threshold");
  });

  it("escapes a pipe so one finding cannot break the table", () => {
    const md = buildReport(ctx({}), {
      failed: false,
      scoped: [
        {
          severity: "high",
          tool: "semgrep",
          ruleId: "r1",
          title: "a | b",
          file: null,
          line: null,
        },
      ],
    });
    expect(md).toContain("a \\| b");
  });

  it("frames scope differently outside a merge request", () => {
    const md = buildReport(ctx({ scope: "schedule" }), {
      failed: false,
      scoped: [],
    });
    expect(md).toContain("not just ones a specific change introduced");
  });
});

describe("prTargetFromEnv", () => {
  it("recognises a pull request run", () => {
    const t = prTargetFromEnv({
      GITHUB_ACTIONS: "true",
      GITHUB_TOKEN: "x",
      GITHUB_REPOSITORY: "org/repo",
      GITHUB_REF: "refs/pull/42/merge",
    });
    expect(t).toMatchObject({
      repo: "org/repo",
      prNumber: 42,
      api: "https://api.github.com",
    });
  });

  it("is null off a pull request, or without a token", () => {
    expect(
      prTargetFromEnv({
        GITHUB_ACTIONS: "true",
        GITHUB_TOKEN: "x",
        GITHUB_REPOSITORY: "o/r",
        GITHUB_REF: "refs/heads/main",
      }),
    ).toBeNull();
    expect(
      prTargetFromEnv({
        GITHUB_ACTIONS: "true",
        GITHUB_REPOSITORY: "o/r",
        GITHUB_REF: "refs/pull/1/merge",
      }),
    ).toBeNull();
    expect(prTargetFromEnv({})).toBeNull();
  });
});

describe("mrTargetFromEnv", () => {
  it("recognises a merge-request pipeline with a token", () => {
    const t = mrTargetFromEnv({
      GITLAB_CI: "true",
      CI_PIPELINE_SOURCE: "merge_request_event",
      CERBERUS_GITLAB_TOKEN: "x",
      CI_PROJECT_ID: "150",
      CI_MERGE_REQUEST_IID: "7",
      CI_SERVER_URL: "https://git.startmatter.com",
    });
    expect(t).toMatchObject({
      api: "https://git.startmatter.com/api/v4",
      projectId: "150",
      mrIid: 7,
    });
  });

  it("is null off a merge request, or without the token", () => {
    expect(
      mrTargetFromEnv({
        GITLAB_CI: "true",
        CI_PIPELINE_SOURCE: "push",
        CERBERUS_GITLAB_TOKEN: "x",
        CI_PROJECT_ID: "150",
        CI_MERGE_REQUEST_IID: "7",
        CI_SERVER_URL: "https://git.startmatter.com",
      }),
    ).toBeNull();
    expect(
      mrTargetFromEnv({
        GITLAB_CI: "true",
        CI_PIPELINE_SOURCE: "merge_request_event",
        CI_PROJECT_ID: "150",
        CI_MERGE_REQUEST_IID: "7",
        CI_SERVER_URL: "https://git.startmatter.com",
      }),
    ).toBeNull();
    expect(mrTargetFromEnv({})).toBeNull();
  });
});
