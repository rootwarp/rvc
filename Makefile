.PHONY: build build-release check fmt clippy test coverage clean

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
	cargo test --workspace

test-verbose:
	cargo test -- --nocapture

# Coverage
coverage:
	cargo llvm-cov --workspace

coverage-html:
	cargo llvm-cov --workspace --html

# Clean
clean:
	cargo clean

# All checks (CI)
ci: fmt-check clippy test
