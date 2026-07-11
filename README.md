# Cerberus

**Cerberus** is a three-headed guard dog for your CI: SAST (Semgrep), secrets (Gitleaks) and dependencies (Trivy) in one container. It merges everything into a single SARIF report, ships it to your tracker, and fails the pipeline only when *new* findings appear — your old backlog never blocks a merge.

> **Status: v0.** The CLI works end-to-end (scan → merge → upload → gate); the Docker image and CI wrappers are not published yet.

## Why another scanner wrapper

Running scanners in CI is easy. Living with the results is not: the first scan dumps hundreds of findings, every pipeline goes red, and a week later someone turns the gate off. Cerberus stays stateless and delegates memory to a backend (a tracker). The backend deduplicates findings across scans and answers with a **delta** — so tasks are created only for new findings, fixed ones are auto-closed, triaged false positives stay silent, and the merge gate reacts to *new* problems only.

## How it works

```
CI job ──▶ cerberus scan
             ├─ Semgrep   (SAST)
             ├─ Gitleaks  (secrets)
             └─ Trivy     (deps / images / IaC)
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

**GitHub** — add the action:

```yaml
- uses: startmatter/cerberus@main
  with:
    url: ${{ secrets.K_SARIF_URL }}
    secret: ${{ secrets.K_SARIF_SECRET }}
```

CI context (repo, branch, commit, author, changed files) is detected from GitLab CI / GitHub Actions
environment variables. `K_SARIF_URL` and `K_SARIF_SECRET` come from the tracker's integration settings —
set them group-level (GitLab) or as org secrets (GitHub) so every repo inherits them. In `auto` mode
the default branch reports (creates/closes tasks) and every other branch checks (read-only gate) — so
one job line covers pushes and merge requests.

Add a nightly scheduled pipeline for dependency scanning: new CVEs land in code that never changed,
so pushes alone will not surface them.

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
