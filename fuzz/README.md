# Fuzz Testing

This directory contains fuzz tests for the AWS Secrets Manager Agent using [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz).

## Overview

Fuzzing helps discover security vulnerabilities and edge cases by feeding malformed inputs to the agent's **public HTTP API**. The fuzz tests focus on the actual attack surface that customers interact with, without exposing internal implementation details.

## Fuzz Targets

### `fuzz_http_api`

Tests the public HTTP endpoints of the Secrets Manager Agent:

- **Query-based requests**: `/secretsmanager/get?secretId=...`
- **Path-based requests**: `/v1/<secret-id>`
- **Health check**: `/ping`

This target fuzzes:
- Secret IDs (names and ARNs)
- Query parameters (`versionStage`, `versionId`, `refreshNow`)
- URL encoding edge cases
- SSRF token validation
- Security header checks (X-Forwarded-For rejection)

## Prerequisites

```bash
# Install Rust nightly (required for cargo-fuzz)
rustup install nightly

# Install cargo-fuzz
cargo install cargo-fuzz
```

## Running Fuzz Tests

### Quick Test (3 minutes)

```bash
cd fuzz
cargo +nightly fuzz run fuzz_http_api -- -max_total_time=180
```

### Extended Fuzzing

```bash
# Run for 1 hour
cargo +nightly fuzz run fuzz_http_api -- -max_total_time=3600

# Run indefinitely (Ctrl+C to stop)
cargo +nightly fuzz run fuzz_http_api
```

### With Custom Options

```bash
# Limit memory usage
cargo +nightly fuzz run fuzz_http_api -- -rss_limit_mb=2048

# Use multiple CPU cores
cargo +nightly fuzz run fuzz_http_api -- -workers=4 -jobs=4

# Combine options
cargo +nightly fuzz run fuzz_http_api -- -max_total_time=600 -workers=4
```

## Reproducing Crashes

If fuzzing finds a crash, it will be saved in `fuzz/artifacts/fuzz_http_api/`:

```bash
# Reproduce a specific crash
cargo +nightly fuzz run fuzz_http_api fuzz/artifacts/fuzz_http_api/crash-<hash>

# Debug with more output
RUST_BACKTRACE=1 cargo +nightly fuzz run fuzz_http_api fuzz/artifacts/fuzz_http_api/crash-<hash>
```

## Corpus Management

The corpus contains test inputs that achieve good code coverage:

```bash
# View corpus
ls fuzz/corpus/fuzz_http_api/

# Add custom test case
echo -n "your-test-input" > fuzz/corpus/fuzz_http_api/custom_test

# Minimize corpus (remove redundant inputs)
cargo +nightly fuzz cmin fuzz_http_api
```

## Coverage Analysis

```bash
# Generate coverage report
cargo +nightly fuzz coverage fuzz_http_api

# View coverage (requires llvm-cov)
cargo cov -- show target/*/release/fuzz_http_api \
    --format=html \
    --instr-profile=fuzz/coverage/fuzz_http_api/coverage.profdata \
    > coverage.html
```

## CI Integration

Fuzz tests run automatically on every PR for 3 minutes per target. See `.github/workflows/fuzz.yml`.

## Design Philosophy

These fuzz tests follow security best practices:

1. **Public API Only**: Tests only the HTTP endpoints customers use, not internal functions
2. **No Module Exposure**: Doesn't require exposing private modules or functions
3. **Real Attack Surface**: Focuses on actual security boundaries (HTTP parsing, auth, SSRF protection)
4. **Comprehensive Coverage**: Tests all public endpoints and security-critical features

This approach ensures fuzzing provides security value without compromising the library's API stability.

## Troubleshooting

### "error: no such subcommand: `fuzz`"

Install cargo-fuzz: `cargo install cargo-fuzz`

### "error: toolchain 'nightly' is not installed"

Install nightly: `rustup install nightly`

### Out of memory errors

Reduce memory limit: `cargo +nightly fuzz run fuzz_http_api -- -rss_limit_mb=1024`

## Resources

- [cargo-fuzz documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer options](https://llvm.org/docs/LibFuzzer.html#options)
- [Rust fuzzing guide](https://rust-fuzz.github.io/book/)