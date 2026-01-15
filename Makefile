.PHONY: build build-release check fmt clippy test clean

# Build
build:
	cargo build

build-release:
	cargo build --release

# Check and lint
check:
	cargo check

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

clippy:
	cargo clippy -- -D warnings

# Test
test:
	cargo test

test-verbose:
	cargo test -- --nocapture

# Clean
clean:
	cargo clean

# All checks (CI)
ci: fmt-check clippy test
