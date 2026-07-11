/** Ship the merged SARIF to the backend as a {meta, sarif} envelope and
 *  return the scan delta (see the K ingest contract). */

import type { CiContext, UploadResponse } from "./types.js";

export interface UploadTarget {
  url: string;
  secret: string;
  headerName: string;
}

/** K_SARIF_URL / K_SARIF_SECRET (+ optional K_SARIF_HEADER). */
export function targetFromEnv(env: Record<string, string | undefined> = process.env): UploadTarget | null {
  const url = env.K_SARIF_URL?.trim();
  const secret = env.K_SARIF_SECRET?.trim();
  if (!url || !secret) return null;
  return { url, secret, headerName: env.K_SARIF_HEADER?.trim() || "X-Webhook-Secret" };
}

export function buildEnvelope(ctx: CiContext, mode: "report" | "check", partial: boolean, sarif: unknown) {
  return {
    meta: {
      repo: ctx.repo,
      branch: ctx.branch,
      baselineBranch: ctx.defaultBranch,
      commit: ctx.commit,
      author: ctx.author,
      changedFiles: ctx.changedFiles,
      mode,
      partial,
    },
    sarif,
  };
}

export async function upload(target: UploadTarget, envelope: unknown): Promise<UploadResponse> {
  const res = await fetch(target.url, {
    method: "POST",
    headers: { "Content-Type": "application/json", [target.headerName]: target.secret },
    body: JSON.stringify(envelope),
  });
  let body: UploadResponse;
  try {
    body = (await res.json()) as UploadResponse;
  } catch {
    body = { ok: false, error: `HTTP ${res.status}` };
  }
  if (!res.ok && body.error === undefined) body.error = `HTTP ${res.status}`;
  return body;
}
