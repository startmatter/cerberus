# Cerberus

**Cerberus** is a three-headed guard dog for your CI: SAST (Semgrep), secrets (Gitleaks) and dependencies (Trivy) in one container. It merges everything into a single SARIF report, ships it to your tracker, and fails the pipeline only when *new* findings appear — your old backlog never blocks a merge.

> **Status: early development.** The contract below is what we are building; nothing is released yet.

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

## Planned usage

```yaml
# .gitlab-ci.yml
security:
  image: ghcr.io/startmatter/cerberus
  script: [cerberus scan]
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

```yaml
# cerberus.yml
scanners:
  semgrep:  { config: p/security-audit }
  gitleaks: {}
  trivy:    { scanners: [vuln, secret, misconfig] }
gate:
  fail_on: new-critical   # new-critical | new-high | any-new | never
```

Locally: `docker run -v $(pwd):/src ghcr.io/startmatter/cerberus scan` — prints a findings table, uploads nothing unless you pass `--upload`.

## Design principles

- **Stateless.** Cerberus scans everything and sends everything. History, dedup, baselines and suppression live in the backend.
- **Delta gate.** Pipelines fail only on findings introduced by the change. A pre-existing backlog never blocks a merge.
- **No second UI.** Triage happens in your tracker: close a task as *declined* and the finding is suppressed forever; close it as *done* and the next scan verifies the fix.
- **Bring your own backend.** The upload contract is a documented JSON envelope around SARIF; any backend implementing it works.

## Roadmap

- [ ] v0: CLI — run scanners, merge SARIF, upload, gate on the response
- [ ] Docker image with pinned scanner versions
- [ ] GitLab CI template and GitHub composite action
- [ ] `check` mode for merge requests (classify against baseline, no writes)
- [ ] MR/PR comments with the delta table
- [ ] More heads: Hadolint, Checkov, license audit, Zizmor

Scanner rules (e.g. the Semgrep registry) are fetched at runtime and are licensed by their respective owners; Cerberus does not bundle them.

## License

[Apache-2.0](LICENSE)
