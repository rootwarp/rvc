# Untracked orphan deletion record

**Date:** 2026-08-12  
**Archive branch:** `archive/untracked-orphans-2026-08-12` @ `51c822d`  
**MANIFEST.md SHA-256:** `4b33f6f0e7d3539639ef4e1bfc2c31e167e52da1f0a472eea486da9b9e9562aa`  
**Tarball:** `plan/architecture-2026-08-12/archive/untracked-orphans-2026-08-12.tar.gz`  
**Tarball SHA-256:** `8b3cda5c2b6f26801d092d8eb7b742826eed661e2bd658c52d51c94be7614dcc`

## Paths removed (untracked; never on develop history)

The following orphan trees were deleted from the working tree after verified archive (ARCH-1a):

1. `crates/rvc-signer/`
2. `crates/rvc-keygen/`
3. `crates/rvc/src/main.rs`
4. `crates/rvc/src/commands/`

## Not touched

- `bin/rvc/src/commands/` (live CLI commands)
- `crates/signer/` (live package `rvc-signer`)
- `crates/rvc/Cargo.toml` (left unchanged; `autobins = false` remains)

## Notes

These paths were untracked and therefore produced no git tree deletions. This file is the auditable record that they were removed after archive verification.
