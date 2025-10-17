#!/bin/bash
set -e

# Local integration test runner
echo "Setting up local integration test environment..."

export AWS_REGION="${AWS_REGION:-us-east-1}"
echo "Using region: $AWS_REGION"

# Build agent (debug for faster builds during testing)
echo "Building agent..."
cargo build

# Run integration tests from the integration-tests crate
echo "Running integration tests..."
cd integration-tests

# Run integration tests sequentially (matches CI behavior)
# Tests handle their own setup and cleanup
cargo test -- --test-threads=1

cd ..

echo "Local integration tests completed!"