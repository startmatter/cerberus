/** Where the report goes: the job summary (always) and the pull request
 *  (when we are running on one and have a token). */

import { appendFileSync } from "node:fs";
import { COMMENT_MARKER } from "./report.js";

type Env = Record<string, string | undefined>;

/** GitHub renders this file on the run's summary page. Free, no token. */
export function writeJobSummary(markdown: string, env: Env = process.env): boolean {
  const path = env.GITHUB_STEP_SUMMARY;
  if (!path) return false;
  try {
    appendFileSync(path, `${markdown}\n`);
    return true;
  } catch {
    return false;
  }
}

interface PrTarget {
  api: string;
  repo: string;
  prNumber: number;
  token: string;
}

/** The pull request this run belongs to, if any. Needs a token with
 *  `pull-requests: write` — absent on forks, which is fine: the summary still
 *  carries the report. */
export function prTargetFromEnv(env: Env = process.env): PrTarget | null {
  if (env.GITHUB_ACTIONS !== "true") return null;
  const token = env.GITHUB_TOKEN?.trim();
  const repo = env.GITHUB_REPOSITORY?.trim();
  const ref = env.GITHUB_REF ?? ""; // refs/pull/123/merge
  const match = /^refs\/pull\/(\d+)\//.exec(ref);
  if (!token || !repo || !match) return null;
  return {
    api: env.GITHUB_API_URL?.trim() || "https://api.github.com",
    repo,
    prNumber: Number(match[1]),
    token,
  };
}

async function gh(target: PrTarget, path: string, init?: RequestInit): Promise<Response> {
  return fetch(`${target.api}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${target.token}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
}

/**
 * Post the report on the pull request, replacing our previous one — a scan runs
 * on every push, and a thread of stale reports is worse than none.
 */
export async function upsertPrComment(target: PrTarget, markdown: string): Promise<"created" | "updated" | "failed"> {
  try {
    const listRes = await gh(target, `/repos/${target.repo}/issues/${target.prNumber}/comments?per_page=100`);
    if (!listRes.ok) return "failed";
    const comments = (await listRes.json()) as Array<{ id: number; body?: string }>;
    const mine = comments.find((c) => c.body?.includes(COMMENT_MARKER));

    const res = mine
      ? await gh(target, `/repos/${target.repo}/issues/comments/${mine.id}`, {
          method: "PATCH",
          body: JSON.stringify({ body: markdown }),
        })
      : await gh(target, `/repos/${target.repo}/issues/${target.prNumber}/comments`, {
          method: "POST",
          body: JSON.stringify({ body: markdown }),
        });

    if (!res.ok) return "failed";
    return mine ? "updated" : "created";
  } catch {
    return "failed";
  }
}
