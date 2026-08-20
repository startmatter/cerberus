/** Shared types: config shape, CI context, findings, gate. */

export type GatePolicy = "new-critical" | "new-high" | "any-new" | "never";

export interface ScannerConfig {
  enabled: boolean;
  /** Extra CLI arguments appended to the scanner invocation. */
  args: string[];
}

export interface SemgrepConfig extends ScannerConfig {
  /** Semgrep ruleset — fetched at runtime, never bundled (registry license). */
  config: string;
}

export interface TrivyConfig extends ScannerConfig {
  scanners: string[];
}

export interface CustomScanner {
  name: string;
  /** Shell command; `{output}` is replaced with the SARIF output path. */
  command: string;
}

export interface CerberusConfig {
  scanners: {
    semgrep: SemgrepConfig;
    gitleaks: ScannerConfig;
    trivy: TrivyConfig;
    /** IaC misconfig: Terraform, CloudFormation, k8s, Dockerfile. */
    checkov: ScannerConfig;
    /** Dockerfile lint (every Dockerfile in the tree). */
    hadolint: ScannerConfig;
    custom: CustomScanner[];
  };
  gate: { failOn: GatePolicy };
}

/**
 * Where and what we are scanning — from CI env vars or local git.
 *
 * `scope` drives the gate: on a `merge_request` it filters findings down to
 * files the change actually touches (`changedFiles`); a `default_branch`
 * push or a scheduled sweep gates on everything found, unscoped — a nightly
 * dependency scan exists precisely to catch new CVEs in code nobody
 * touched, so it must not be diff-scoped away to nothing. `tag` (a release
 * pipeline) and `local` never gate at all: the tagged commit was already
 * scanned and gated on its merge request, and re-running an unscoped sweep
 * on every release would fail deploys over pre-existing, unrelated CVEs
 * instead of anything that release actually changed.
 */
export interface CiContext {
  provider: "gitlab" | "github" | "local";
  scope: "merge_request" | "default_branch" | "schedule" | "tag" | "local";
  repo: string;
  branch: string;
  defaultBranch: string;
  commit?: string;
  author?: string;
  changedFiles: string[];
}

export interface ScannerRun {
  name: string;
  ok: boolean;
  /** Parsed SARIF log (undefined when the scanner failed or produced nothing). */
  sarif?: unknown;
  error?: string;
  durationMs: number;
}

/** One SARIF result, flattened for local (backend-free) gating and reporting. */
export interface FlatFinding {
  severity: string;
  tool: string;
  ruleId: string;
  title: string;
  file: string | null;
  line: number | null;
}

export interface GateResult {
  failed: boolean;
  reason?: string;
  /** The findings actually considered — diff-scoped on a merge request, everything otherwise. */
  scoped: FlatFinding[];
}
