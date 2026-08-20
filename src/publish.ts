/** Where the report goes: the job summary (GitHub, always), and a comment on
 *  the pull/merge request when we're running on one and have a token. */

import { appendFileSync } from "node:fs";
import { COMMENT_MARKER } from "./report.js";

type Env = Record<string, string | undefined>;

/** GitHub renders this file on the run's summary page. Free, no token. */
export function writeJobSummary(
  markdown: string,
  env: Env = process.env,
): boolean {
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

async function gh(
  target: PrTarget,
  path: string,
  init?: RequestInit,
): Promise<Response> {
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
export async function upsertPrComment(
  target: PrTarget,
  markdown: string,
): Promise<"created" | "updated" | "failed"> {
  try {
    const listRes = await gh(
      target,
      `/repos/${target.repo}/issues/${target.prNumber}/comments?per_page=100`,
    );
    if (!listRes.ok) return "failed";
    const comments = (await listRes.json()) as Array<{
      id: number;
      body?: string;
    }>;
    const mine = comments.find((c) => c.body?.includes(COMMENT_MARKER));

    const res = mine
      ? await gh(target, `/repos/${target.repo}/issues/comments/${mine.id}`, {
          method: "PATCH",
          body: JSON.stringify({ body: markdown }),
        })
      : await gh(
          target,
          `/repos/${target.repo}/issues/${target.prNumber}/comments`,
          {
            method: "POST",
            body: JSON.stringify({ body: markdown }),
          },
        );

    if (!res.ok) return "failed";
    return mine ? "updated" : "created";
  } catch {
    return "failed";
  }
}

interface MrTarget {
  api: string;
  /** CI_PROJECT_ID — numeric, safe unencoded, but encoded anyway for consistency. */
  projectId: string;
  mrIid: number;
  token: string;
}

/**
 * The merge request this run belongs to, if any. GitLab's own CI_JOB_TOKEN
 * cannot create notes (its API access is read-only for merge-request notes),
 * so this needs a real bot token — CERBERUS_GITLAB_TOKEN, set group-level,
 * the same pattern already used in production for codex-review's own
 * MR commenting (CODEX_GITLAB_BOT_TOKEN).
 */
export function mrTargetFromEnv(env: Env = process.env): MrTarget | null {
  if (env.GITLAB_CI !== "true") return null;
  if (env.CI_PIPELINE_SOURCE !== "merge_request_event") return null;
  const token = env.CERBERUS_GITLAB_TOKEN?.trim();
  const projectId = env.CI_PROJECT_ID?.trim();
  const iid = env.CI_MERGE_REQUEST_IID?.trim();
  const server = env.CI_SERVER_URL?.trim();
  if (!token || !projectId || !iid || !server) return null;
  return {
    api: `${server.replace(/\/+$/, "")}/api/v4`,
    projectId,
    mrIid: Number(iid),
    token,
  };
}

async function gl(
  target: MrTarget,
  path: string,
  init?: RequestInit,
): Promise<Response> {
  return fetch(`${target.api}${path}`, {
    ...init,
    headers: {
      "PRIVATE-TOKEN": target.token,
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
}

/** Same upsert-by-marker pattern as `upsertPrComment`, against GitLab's notes API. */
export async function upsertMrNote(
  target: MrTarget,
  markdown: string,
): Promise<"created" | "updated" | "failed"> {
  try {
    const project = encodeURIComponent(target.projectId);
    const listRes = await gl(
      target,
      `/projects/${project}/merge_requests/${target.mrIid}/notes?per_page=100`,
    );
    if (!listRes.ok) return "failed";
    const notes = (await listRes.json()) as Array<{
      id: number;
      body?: string;
    }>;
    const mine = notes.find((n) => n.body?.includes(COMMENT_MARKER));

    const res = mine
      ? await gl(
          target,
          `/projects/${project}/merge_requests/${target.mrIid}/notes/${mine.id}`,
          {
            method: "PUT",
            body: JSON.stringify({ body: markdown }),
          },
        )
      : await gl(
          target,
          `/projects/${project}/merge_requests/${target.mrIid}/notes`,
          {
            method: "POST",
            body: JSON.stringify({ body: markdown }),
          },
        );

    if (!res.ok) return "failed";
    return mine ? "updated" : "created";
  } catch {
    return "failed";
  }
}
