# Cerberus

**Cerberus** is a guard dog for your CI: SAST (Semgrep), secrets (Gitleaks), dependencies (Trivy), IaC misconfig (Checkov) and Dockerfile lint (Hadolint) in one container. It merges everything into a single SARIF report, ships it to your tracker, and fails the pipeline only when *new* findings appear — your old backlog never blocks a merge.

> **Status: v0.** The CLI works end-to-end (scan → merge → upload → gate); the Docker image and CI wrappers are not published yet.

## Why another scanner wrapper

Running scanners in CI is easy. Living with the results is not: the first scan dumps hundreds of findings, every pipeline goes red, and a week later someone turns the gate off. Cerberus stays stateless and delegates memory to a backend (a tracker). The backend deduplicates findings across scans and answers with a **delta** — so tasks are created only for new findings, fixed ones are auto-closed, triaged false positives stay silent, and the merge gate reacts to *new* problems only.

## How it works

```
CI job ──▶ cerberus scan
             ├─ Semgrep   (SAST)
             ├─ Gitleaks  (secrets, whole history)
             ├─ Trivy     (dependencies, secrets, misconfig)
             ├─ Checkov   (IaC misconfig)
             ├─ Hadolint  (Dockerfiles)
             └─ custom    (anything that writes SARIF)
                   │ merge → one SARIF
                   ▼
             POST to backend  ──▶ dedup, lifecycle, tasks
                   ◀── { new: 1, known: 51, fixed: 3 }
                   │
             exit code by gate policy (fail_on: new-critical)
```

## Usage

**GitLab** — include the template:

```yaml
include:
  - remote: https://raw.githubusercontent.com/startmatter/cerberus/main/templates/gitlab-ci.yml
```

**GitHub** — call the reusable workflow:

```yaml
permissions:
  contents: read
  packages: read

jobs:
  security:
    uses: startmatter/cerberus/.github/workflows/scan.yml@main
    secrets:
      K_SARIF_URL: ${{ secrets.K_SARIF_URL }}
      K_SARIF_SECRET: ${{ secrets.K_SARIF_SECRET }}
```

Or drive the action directly when you need control over the surrounding job:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0          # Gitleaks scans the whole history
- uses: startmatter/cerberus@main
  with:
    url: ${{ secrets.K_SARIF_URL }}
    secret: ${{ secrets.K_SARIF_SECRET }}
    # dns: 1.1.1.1,8.8.8.8  # self-hosted runners whose resolver containers can't reach
```

CI context (repo, branch, commit, author, changed files) is detected from GitLab CI / GitHub Actions
environment variables. `K_SARIF_URL` and `K_SARIF_SECRET` come from the tracker's integration settings —
set them group-level (GitLab) or as org secrets (GitHub) so every repo inherits them. In `auto` mode
the default branch reports (creates/closes tasks) and every other branch checks (read-only gate) — so
one job line covers pushes and merge requests.

Add a nightly scheduled pipeline for dependency scanning: new CVEs land in code that never changed,
so pushes alone will not surface them.

### Self-hosted runners

If the runner sits behind a VPN resolver its containers cannot reach, Semgrep cannot fetch its rules
and Trivy cannot fetch its vulnerability database — and both quietly produce an empty report. Pass
`dns: 1.1.1.1,8.8.8.8` (GitHub) or set `--dns` on the runner's docker config (GitLab).

### Pulling a private image

Container packages are private by default, and some organizations disallow public ones. Then the
runner has to authenticate:

- **GitLab** — add a `DOCKER_AUTH_CONFIG` CI variable (group-level):
  `{"auths":{"ghcr.io":{"auth":"<base64 of user:token>"}}}` where the token is a GitHub PAT with
  `read:packages`.
- **GitHub, same organization** — nothing to do: the action logs in with the job's `GITHUB_TOKEN`.
  Give the job `permissions: packages: read`.
- **GitHub, another organization** — a repository's own token cannot read another org's private
  package. Pass a PAT with `read:packages` as the `REGISTRY_TOKEN` secret (reusable workflow) or
  `registry-token` input (action).

Configuration lives in [`cerberus.yml`](cerberus.example.yml) in the repo root — scanners, extra args,
custom SARIF-emitting checks, gate policy.

Locally: `docker run -v $(pwd):/src ghcr.io/startmatter/cerberus scan` — prints a findings table,
uploads nothing unless you pass `--upload`. Exit codes: 0 clean, 1 gate failed, 2 runtime error.

## Design principles

- **Stateless.** Cerberus scans everything and sends everything. History, dedup, baselines and suppression live in the backend.
- **Delta gate.** Pipelines fail only on findings introduced by the change. A pre-existing backlog never blocks a merge.
- **No second UI.** Triage happens in your tracker: close a task as *declined* and the finding is suppressed forever; close it as *done* and the next scan verifies the fix.
- **Bring your own backend.** The upload contract is a documented JSON envelope around SARIF; any backend implementing it works.

## Roadmap

- [x] v0: CLI — run scanners, merge SARIF, upload, gate on the response
- [x] Dockerfile with pinned scanner versions
- [x] `check` mode for merge requests (classify against baseline, no writes)
- [x] GitLab CI template and GitHub composite action
- [x] Image published to ghcr.io on every push to main
- [ ] MR/PR comments with the delta table
- [ ] More heads: Hadolint, Checkov, license audit, Zizmor

Scanner rules (e.g. the Semgrep registry) are fetched at runtime and are licensed by their respective owners; Cerberus does not bundle them.

## License

[Apache-2.0](LICENSE)
