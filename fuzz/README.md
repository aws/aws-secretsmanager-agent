# Fuzz Testing

The AWS Secrets Manager Agent includes fuzz tests to discover security vulnerabilities, edge cases, and potential crashes by feeding malformed, unexpected, or random inputs to critical components.

## Overview

Fuzz testing uses [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) with libFuzzer to automatically generate test inputs and discover bugs in:

- **Query Parser** (`fuzz_query_parser`) - Tests URL query parameter and path-based request parsing
- **Token Validator** (`fuzz_token_validator`) - Tests SSRF token validation and file:// path handling

## Prerequisites

- Rust nightly toolchain
- cargo-fuzz

## Installation

Install the required tools:

```sh
# Install Rust nightly
rustup toolchain install nightly

# Install cargo-fuzz
cargo install cargo-fuzz
```

## Running Fuzz Tests Locally

### Quick Test (30 seconds per target)

Run each fuzz target for 30 seconds to verify it works:

```sh
# Test query parser
cargo +nightly fuzz run fuzz_query_parser -- -max_total_time=30

# Test token validator
cargo +nightly fuzz run fuzz_token_validator -- -max_total_time=30
```

### Extended Fuzzing

For more thorough testing, run for longer periods:

```sh
# Run for 10 minutes
cargo +nightly fuzz run fuzz_query_parser -- -max_total_time=600

# Run indefinitely (stop with Ctrl+C)
cargo +nightly fuzz run fuzz_query_parser
```

### List Available Targets

```sh
cargo +nightly fuzz list
```

## Reproducing Crashes

When a fuzzer discovers a crash, it saves the input to `fuzz/artifacts/<target>/crash-<hash>`.

To reproduce a crash:

```sh
# Replay the exact input that caused the crash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
```

Example:

```sh
cargo +nightly fuzz run fuzz_query_parser fuzz/artifacts/fuzz_query_parser/crash-abc123
```

### Minimizing Crash Inputs

To find the smallest input that still triggers the crash:

```sh
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<hash>
```

This helps identify the root cause by removing unnecessary bytes from the crashing input.

## Continuous Integration

Fuzz tests run automatically on every pull request via GitHub Actions (`.github/workflows/fuzz.yml`):

- Each target runs for 2 minutes
- Crashes fail the build
- Crash artifacts are uploaded for debugging

## Corpus Management

The corpus contains seed inputs that guide the fuzzer:

```
fuzz/corpus/
├── fuzz_query_parser/     # Seed inputs for query parser
└── fuzz_token_validator/  # Seed inputs for token validator
```

### Adding Seed Inputs

To add a new seed input:

1. Create a file in the appropriate corpus directory
2. Add representative input data (valid or interesting edge cases)
3. Commit the file to git

Example:

```sh
echo "secretId=test&versionId=v1" > fuzz/corpus/fuzz_query_parser/seed_with_version
```

The fuzzer will use these seeds as starting points to generate new test cases.

## Understanding Fuzzer Output

During fuzzing, you'll see output like:

```
#12345  NEW    cov: 234 ft: 567 corp: 89/1234b lim: 4096 exec/s: 1234
```

- `NEW` - Found new coverage
- `cov: 234` - Total edge coverage
- `ft: 567` - Feature coverage
- `corp: 89/1234b` - Corpus size (89 inputs, 1234 bytes)
- `exec/s: 1234` - Executions per second

## Troubleshooting

### Fuzzer Won't Start

If you see "error: no such subcommand: `fuzz`":

```sh
# Reinstall cargo-fuzz
cargo install cargo-fuzz --force
```

### Out of Memory

If fuzzing crashes with OOM errors, reduce the memory limit:

```sh
cargo +nightly fuzz run <target> -- -rss_limit_mb=2048
```

### Slow Fuzzing

If fuzzing is slow (< 1000 exec/s), try:

1. Build in release mode (cargo-fuzz does this by default)
2. Close other applications
3. Use a simpler seed corpus

## Additional Resources

- [cargo-fuzz documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer options](https://llvm.org/docs/LibFuzzer.html#options)
- [Rust Fuzz Book](https://rust-fuzz.github.io/book/)
