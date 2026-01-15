# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

rs-vc is a Rust-based Validator Client.

## Commands

```bash
# Build
cargo build
cargo build --release

# Check and lint
cargo check
cargo fmt
cargo clippy

# Test
cargo test
cargo test test_name              # Run single test
cargo test -- --nocapture         # Run with output
```

## Git Workflow

- `main` branch: primary branch
- `develop` branch: development branch

## Code Conventions

### Naming
- `snake_case` for functions, methods, variables, modules, and crates
- `PascalCase` for types, traits, and enum variants
- `SCREAMING_SNAKE_CASE` for constants and statics
- Prefix unused variables with `_`

### Error Handling
- Use `Result<T, E>` for recoverable errors
- Use `?` operator for error propagation
- Define custom error types with `thiserror` for libraries or `anyhow` for applications
- Avoid `.unwrap()` in production code; prefer `.expect("reason")` when panicking is intentional

### Style
- Run `cargo fmt` before committing
- Run `cargo clippy` and address warnings
- Prefer `impl Trait` over `dyn Trait` when possible
- Use `Self` to refer to the implementing type in impl blocks
- Prefer iterators and combinators over manual loops when clearer

### Documentation
- Use `///` for public API documentation
- Use `//!` for module-level documentation
- Include examples in doc comments for public functions

## Testing

### Organization
- Place unit tests in a `#[cfg(test)]` module at the bottom of each file
- Place integration tests in `tests/` directory
- Use descriptive test names: `test_function_does_expected_behavior`

### TDD Cycle (Kent Beck)

Follow the RED → GREEN → REFACTOR cycle:

1. **RED**: Write a failing test first
   - Define the expected behavior before writing implementation
   - Run the test and confirm it fails for the right reason

2. **GREEN**: Write the minimum code to make the test pass
   - Focus only on making the test pass
   - Don't worry about elegance or optimization yet

3. **REFACTOR**: Improve the code while keeping tests green
   - Remove duplication
   - Improve naming and structure
   - Ensure all tests still pass after changes

Repeat this cycle for each new piece of functionality.
