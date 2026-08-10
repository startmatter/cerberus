/** Ship the merged SARIF to the backend as a {meta, sarif} envelope and
 *  return the scan delta (see the K ingest contract).
 *
 *  Two auth schemes: a member API key against the tracker's generic API
 *  (preferred — no per-project secret to manage), or the legacy per-project
 *  webhook secret. Both hit the same ingest logic on the other end and
 *  return the same response shape. */

import type { CiContext, UploadResponse } from "./types.js";

export type UploadTarget =
  | { kind: "api"; url: string; apiKey: string; projectId: string }
  | { kind: "legacy"; url: string; secret: string; headerName: string };

/**
 * K_API_URL + K_API_KEY + K_PROJECT_ID (preferred) — url is the tracker's
 * base URL, e.g. https://up.startmatter.com, not a full endpoint.
 * Falls back to the legacy K_SARIF_URL + K_SARIF_SECRET (+ optional
 * K_SARIF_HEADER) — url there IS the full per-project ingest URL.
 */
export function targetFromEnv(
  env: Record<string, string | undefined> = process.env,
): UploadTarget | null {
  const apiUrl = env.K_API_URL?.trim();
  const apiKey = env.K_API_KEY?.trim();
  const projectId = env.K_PROJECT_ID?.trim();
  if (apiUrl && apiKey && projectId) {
    return { kind: "api", url: apiUrl.replace(/\/+$/, ""), apiKey, projectId };
  }

  const url = env.K_SARIF_URL?.trim();
  const secret = env.K_SARIF_SECRET?.trim();
  if (url && secret) {
    return {
      kind: "legacy",
      url,
      secret,
      headerName: env.K_SARIF_HEADER?.trim() || "X-Webhook-Secret",
    };
  }
  return null;
}

export function buildEnvelope(
  ctx: CiContext,
  mode: "report" | "check",
  partial: boolean,
  sarif: unknown,
) {
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

export async function upload(
  target: UploadTarget,
  envelope: { meta: unknown; sarif: unknown },
): Promise<UploadResponse> {
  const {
    url,
    headers,
    body: requestBody,
  } = target.kind === "api"
    ? {
        url: `${target.url}/api/v1/scan/ingest`,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${target.apiKey}`,
        },
        body: JSON.stringify({ projectId: target.projectId, ...envelope }),
      }
    : {
        url: target.url,
        headers: {
          "Content-Type": "application/json",
          [target.headerName]: target.secret,
        },
        body: JSON.stringify(envelope),
      };

  const res = await fetch(url, { method: "POST", headers, body: requestBody });
  let body: UploadResponse;
  try {
    body = (await res.json()) as UploadResponse;
  } catch {
    body = { ok: false, error: `HTTP ${res.status}` };
  }
  if (!res.ok && body.error === undefined) body.error = `HTTP ${res.status}`;
  return body;
}
