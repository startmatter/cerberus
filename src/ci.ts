/** CI context detection: GitLab CI, GitHub Actions, or local git. */

import { execFileSync } from "node:child_process";
import { basename } from "node:path";
import type { CiContext } from "./types.js";

type Env = Record<string, string | undefined>;

function git(cwd: string, args: string[]): string | undefined {
  try {
    return (
      execFileSync("git", args, {
        cwd,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim() || undefined
    );
  } catch {
    return undefined;
  }
}

/** Files touched by the latest commit(s) — best effort, empty when unknown. */
function changedFiles(cwd: string, fromSha?: string): string[] {
  const NO_SHA = /^0+$/;
  const range =
    fromSha && !NO_SHA.test(fromSha) ? `${fromSha}..HEAD` : "HEAD~1..HEAD";
  const out = git(cwd, ["diff", "--name-only", range]);
  return out ? out.split("\n").filter(Boolean).slice(0, 2000) : [];
}

/** Merge-base with a remote branch ref, if it resolves locally — undefined
 *  (not thrown) when the ref was never fetched, so callers can fall back. */
function mergeBaseWith(cwd: string, ref: string): string | undefined {
  return git(cwd, ["merge-base", "HEAD", ref]);
}

export function detectCi(cwd: string, env: Env = process.env): CiContext {
  if (env.GITLAB_CI === "true") {
    const isMr = env.CI_PIPELINE_SOURCE === "merge_request_event";
    const scope: CiContext["scope"] = isMr
      ? "merge_request"
      : env.CI_COMMIT_TAG
        ? "tag"
        : env.CI_PIPELINE_SOURCE === "schedule"
          ? "schedule"
          : "default_branch";
    // GitLab hands us the MR's actual diff base directly — far more accurate
    // than CI_COMMIT_BEFORE_SHA, which only reflects the most recent push
    // and under-reports across multi-push MRs.
    const diffBase = isMr
      ? env.CI_MERGE_REQUEST_DIFF_BASE_SHA
      : env.CI_COMMIT_BEFORE_SHA;
    return {
      provider: "gitlab",
      scope,
      repo: env.CI_PROJECT_NAME ?? basename(cwd),
      branch: env.CI_COMMIT_BRANCH ?? env.CI_COMMIT_REF_NAME ?? "main",
      defaultBranch: env.CI_DEFAULT_BRANCH ?? "main",
      commit: env.CI_COMMIT_SHA,
      author: env.CI_COMMIT_AUTHOR,
      changedFiles: changedFiles(cwd, diffBase),
    };
  }

  if (env.GITHUB_ACTIONS === "true") {
    const isPr =
      env.GITHUB_EVENT_NAME === "pull_request" ||
      env.GITHUB_EVENT_NAME === "pull_request_target";
    const scope: CiContext["scope"] = isPr
      ? "merge_request"
      : env.GITHUB_REF?.startsWith("refs/tags/")
        ? "tag"
        : env.GITHUB_EVENT_NAME === "schedule"
          ? "schedule"
          : "default_branch";
    // GitHub's checkout has no PR-base SHA handed to us directly — try the
    // merge-base against the fetched base branch ref; fall back to the plain
    // last-commit diff (today's behavior) if that ref isn't available.
    const diffBase =
      isPr && env.GITHUB_BASE_REF
        ? mergeBaseWith(cwd, `origin/${env.GITHUB_BASE_REF}`)
        : undefined;
    const repoPath = env.GITHUB_REPOSITORY ?? ""; // owner/name
    return {
      provider: "github",
      scope,
      repo: repoPath.split("/")[1] || basename(cwd),
      branch: env.GITHUB_HEAD_REF || env.GITHUB_REF_NAME || "main",
      defaultBranch: env.GITHUB_DEFAULT_BRANCH ?? "main",
      commit: env.GITHUB_SHA,
      author: env.GITHUB_ACTOR,
      changedFiles: changedFiles(cwd, diffBase),
    };
  }

  return {
    provider: "local",
    scope: "local",
    repo: basename(git(cwd, ["rev-parse", "--show-toplevel"]) ?? cwd),
    branch: git(cwd, ["branch", "--show-current"]) ?? "main",
    defaultBranch: "main",
    commit: git(cwd, ["rev-parse", "HEAD"]),
    author: git(cwd, ["config", "user.email"]),
    changedFiles: [],
  };
}
