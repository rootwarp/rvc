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
- Self-check (paste into PR body):
  - [ ] Red check: each new acceptance test shown failing on base or with the fix removed.
  - [ ] Measurement claims ("no regression") come from a scenario where unfixed code scores worse.
  - [ ] Repo-wide grep for every changed symbol/pattern the issue targets.
  - [ ] Signing-root / `hash_tree_root` tests are KAT-anchored or `kat_exempt` with a reason.

## Coding
Follow `.cursor/rules/rust-code.mdc` (TDD, idiomatic Rust, conventions) and `CLAUDE.md`.
