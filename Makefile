.PHONY: build build-release check fmt clippy test test-fast coverage clean \
       docker-rvc docker-signer docker-keygen docker-all architecture-doc \
       spec-vectors spec-vectors-verify spec-vectors-regen spec-kat

# Build
build:
	cargo build

build-release:
	cargo build --release

# Docker
docker-rvc:
	docker build --target rvc -t rvc:latest .

docker-signer:
	docker build --target rvc-signer -t rvc-signer:latest .

docker-keygen:
	docker build --target rvc-keygen -t rvc-keygen:latest .

docker-all: docker-rvc docker-signer docker-keygen

# Check and lint
check:
	cargo check

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings
	cargo clippy -p rvc-signer-bin --all-targets --features dvt -- -D warnings

# Test
test:
	cargo test --workspace

test-verbose:
	cargo test -- --nocapture

# Fast tests via cargo-nextest (install once: cargo install cargo-nextest --locked).
# Falls back to plain cargo test if nextest is missing.
test-fast:
	@if command -v cargo-nextest >/dev/null 2>&1; then \
		cargo nextest run --workspace ; \
	else \
		echo "cargo-nextest not installed; falling back to cargo test --workspace" ; \
		echo "Install with: cargo install cargo-nextest --locked" ; \
		cargo test --workspace ; \
	fi

# Coverage
coverage:
	cargo llvm-cov --workspace

coverage-html:
	cargo llvm-cov --workspace --html

# Clean
clean:
	cargo clean

# Regenerate ARCHITECTURE.md crate-count + dependency graph from cargo metadata.
# CI enforces doc == generated via crates/architecture-tests.
architecture-doc:
	cargo run -p rvc-architecture-tests --bin generate-architecture-md

# Fetched consensus-specs / ssz-specs vector cache (gitignored).
# Export rather than splicing PRESET into the recipe (values with quotes/spaces).
PRESET ?= minimal
export PRESET

spec-vectors:
	./scripts/fetch_spec_vectors.sh

# Digest-check tracked pyspec artifacts ([[generated]] in vectors.lock). No Python.
spec-vectors-verify:
	./scripts/fetch_spec_vectors.sh verify

# Re-run the pinned pyspec recipe. Nightly only; PR jobs verify the digest.
spec-vectors-regen:
	./scripts/fetch_spec_vectors.sh regen

# Codegen SPEC_PROGRESSIVE_* / SPEC_GLOAS_* / KAT_GLOAS_* from artifacts + the
# 3.3a fixture tree (no network). --vectors is the fixture tree so regeneration
# stays hermetic; L1 roots come from vectors-generated/progressive/roots.yaml
# (pyspec pre-images), never JSON mix_in_length. Gloas signing roots are copied
# from vectors-generated/signing-roots/signing_roots.yaml (D28).
spec-kat:
	cargo run -p rvc-spec-vectors --bin gen-spec-kat -- \
		--vectors crates/rvc-spec-vectors/tests/fixtures \
		--out crates/rvc-spec-vectors/src/spec_kat.rs

# All checks (CI)
ci: fmt-check clippy test
