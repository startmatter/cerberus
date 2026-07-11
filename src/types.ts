/** Shared types: config shape, CI context, backend contract. */

export type GatePolicy = "new-critical" | "new-high" | "any-new" | "never";
export type UploadMode = "auto" | "report" | "check" | "off";

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
  upload: { mode: UploadMode; partial: boolean };
}

/** Where and what we are scanning — from CI env vars or local git. */
export interface CiContext {
  provider: "gitlab" | "github" | "local";
  repo: string;
  branch: string;
  defaultBranch: string;
  commit?: string;
  author?: string;
  changedFiles: string[];
}

/** The backend's scan-delta response (see the K ingest contract). */
export interface UploadResponse {
  ok: boolean;
  mode?: string;
  baseline?: boolean;
  truncated?: boolean;
  error?: string;
  /** Set when the backend accepted findings but could not turn them into work. */
  taskError?: string;
  summary?: {
    total: number;
    new: number;
    known: number;
    suppressed: number;
    fixed: number;
    reopened: number;
    tasksCreated: number;
    taskFailures?: number;
  };
  new?: Array<{
    title: string;
    severity: string;
    file: string | null;
    line: number | null;
    taskId: string | null;
    /** Human-facing task id (e.g. SID/T/12) and a link straight to it. */
    taskKey?: string | null;
    taskUrl?: string | null;
  }>;
}

export interface ScannerRun {
  name: string;
  ok: boolean;
  /** Parsed SARIF log (undefined when the scanner failed or produced nothing). */
  sarif?: unknown;
  error?: string;
  durationMs: number;
}

export interface GateResult {
  failed: boolean;
  reason?: string;
}
