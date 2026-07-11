/** CI context detection: GitLab CI, GitHub Actions, or local git. */

import { execFileSync } from "node:child_process";
import { basename } from "node:path";
import type { CiContext } from "./types.js";

type Env = Record<string, string | undefined>;

function git(cwd: string, args: string[]): string | undefined {
  try {
    return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || undefined;
  } catch {
    return undefined;
  }
}

/** Files touched by the latest commit(s) — best effort, empty when unknown. */
function changedFiles(cwd: string, fromSha?: string): string[] {
  const NO_SHA = /^0+$/;
  const range = fromSha && !NO_SHA.test(fromSha) ? `${fromSha}..HEAD` : "HEAD~1..HEAD";
  const out = git(cwd, ["diff", "--name-only", range]);
  return out ? out.split("\n").filter(Boolean).slice(0, 2000) : [];
}

export function detectCi(cwd: string, env: Env = process.env): CiContext {
  if (env.GITLAB_CI === "true") {
    return {
      provider: "gitlab",
      repo: env.CI_PROJECT_NAME ?? basename(cwd),
      branch: env.CI_COMMIT_BRANCH ?? env.CI_COMMIT_REF_NAME ?? "main",
      defaultBranch: env.CI_DEFAULT_BRANCH ?? "main",
      commit: env.CI_COMMIT_SHA,
      author: env.CI_COMMIT_AUTHOR,
      changedFiles: changedFiles(cwd, env.CI_COMMIT_BEFORE_SHA),
    };
  }

  if (env.GITHUB_ACTIONS === "true") {
    const repoPath = env.GITHUB_REPOSITORY ?? ""; // owner/name
    return {
      provider: "github",
      repo: repoPath.split("/")[1] || basename(cwd),
      branch: env.GITHUB_HEAD_REF || env.GITHUB_REF_NAME || "main",
      defaultBranch: env.GITHUB_DEFAULT_BRANCH ?? "main",
      commit: env.GITHUB_SHA,
      author: env.GITHUB_ACTOR,
      changedFiles: changedFiles(cwd),
    };
  }

  return {
    provider: "local",
    repo: basename(git(cwd, ["rev-parse", "--show-toplevel"]) ?? cwd),
    branch: git(cwd, ["branch", "--show-current"]) ?? "main",
    defaultBranch: "main",
    commit: git(cwd, ["rev-parse", "HEAD"]),
    author: git(cwd, ["config", "user.email"]),
    changedFiles: [],
  };
}
