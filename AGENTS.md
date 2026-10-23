# AGENTS.md

Guidance for coding agents (Cursor, Claude Code, Codex) working in rvc. `CLAUDE.md` holds project commands and code conventions; this file adds the workflow. Both apply.

## Workflow (hard rules)
- One issue = one branch, created from **current `develop`** (never `main`, never another feature branch).
- Scope = that issue only. Adjacent problems go in a new issue, not this branch.
- Exactly **one commit ahead of `develop`** when the PR opens. Squash first. Review fixes amend that commit and force-push the same branch; never open a superseding branch/PR.
- Commit author: `Joonkyo Kim <rootwarp@gmail.com>`.
- PR base = `develop`, linked to the issue. Body states acceptance criteria and how tests cover them, plus the pre-PR self-check below.
- Merge into `develop` is fast-forward/rebase only, done by the lead. Agents do not merge.
- **No self-review.** Do not run a code-review or review pass on your own PR. Reviews are done only by Harper (Codex code reviewer) and the Rust Security Auditor.

## Before opening the PR
- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test` (workspace, or `-p` for touched crates plus dependents)
- `gitleaks detect --no-git --source . --config .gitleaks.toml --ignore-gitleaks-allow --redact --no-banner --exit-code 1`
- History scan: `gitleaks detect --source . --config .gitleaks.toml --ignore-gitleaks-allow --redact --no-banner --exit-code 1`
- `git diff --shortstat develop...HEAD` = N gross lines; cap 2,000 including tests and generated content; stop at 1,800 and report.
- Self-check (paste into PR body):
  - [ ] Red check: each new acceptance test shown failing on base or with the fix removed.
  - [ ] Measurement claims ("no regression") come from a scenario where unfixed code scores worse.
  - [ ] Repo-wide grep for every changed symbol/pattern the issue targets.
  - [ ] Signing-root / `hash_tree_root` tests are KAT-anchored or `kat_exempt` with a reason.

## Tests
`cargo nextest run --workspace --all-features` is the default. `cargo test` still runs the suite and is what the pre-PR line below names; it shares one process per test binary, so process-global metrics can race. Timing tests use paused tokio time. Do not synchronize a test on a wall-clock sleep.

## Coding
Follow `.cursor/rules/rust-code.mdc` (TDD, idiomatic Rust, conventions) and `CLAUDE.md`.

## Spawn census
`plan/tracing-2026-08-06/spawn-census.md` is checked by `census_anchors_match_sources`. Classify new spawn sites; anchors follow the code. A new executor or bn-manager spawn needs a content row (file, enclosing item, and task or call). A line number is not a key.

## CI action pins
Third-party `uses:` in `.github/workflows` are full commit SHAs with a `# vX.Y.Z` comment on the same line. First-party `actions/*` and `github/*` stay on major tags.
Tagging and releases are lead-only. Do not retag or re-run a release whose workflow still names a missing action ref. Publish images from a tag that contains the corrected workflow.
Resolve a pin with `gh api repos/<owner>/<repo>/git/ref/tags/<tag>`. If `object.type` is `tag`, dereference `git/tags/<object.sha>` and pin the commit, not the tag object. Confirm the ref exists before pushing. Confirm the commit is on the upstream default branch: `gh api repos/<owner>/<repo>/compare/<default>...<sha>` must report `status` `behind` or `identical`. Reject an annotated tag whose `tagger.date` is within 7 days, and treat a lightweight tag whose commit is only a few days old as not yet reviewed.
`dtolnay/rust-toolchain` SHAs must be in `master` history (tag `v1` today); set `with: toolchain: stable`. `taiki-e/install-action` is the `v2` release commit; set `with: tool:`.
`aquasecurity/trivy-action` is pinned in both `docker.yml` and `docker-scan.yml`. Keep those `uses:` lines identical. SARIF output ignores `severity` unless `limit-severities-for-sarif: true`; both workflows set that flag, so `exit-code: '1'` applies to CRITICAL only. `.trivyignore` allows only CVE-2023-45853 (Debian `will_not_fix`: the bug is in minizip, which `zlib1g` does not ship; review by 2027-01-18). Do not set `ignore-unfixed`.
