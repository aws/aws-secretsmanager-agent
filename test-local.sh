#!/bin/bash
set -e

# Local integration test runner
echo "Setting up local integration test environment..."

# Generate unique test prefix
TEST_PREFIX="aws-sm-agent-test-local-$(date +%s)"
export TEST_SECRET_PREFIX="$TEST_PREFIX"
export AWS_REGION="${AWS_REGION:-us-east-1}"

echo "Using test prefix: $TEST_PREFIX"
echo "Using region: $AWS_REGION"

# Create test secrets
echo "Creating test secrets..."

# Basic secret for name/ARN tests
aws secretsmanager create-secret \
  --name "$TEST_PREFIX-basic" \
  --description "Basic test secret for aws-secretsmanager-agent" \
  --secret-string '{"username":"testuser","password":"testpass123"}' \
  --tags '[{"Key":"Purpose","Value":"Local-Test"},{"Key":"TestRun","Value":"'$TEST_PREFIX'"}]'

# Build agent (debug for faster builds during testing)
echo "Building agent..."
cargo build

# Run tests from the workspace root
echo "Running integration tests..."
cd aws_secretsmanager_agent

# Run all integration test files
TEST_SECRET_PREFIX="$TEST_PREFIX" cargo test --test secret_retrieval -- --test-threads=1

cd ..

# Cleanup
echo "Cleaning up test secrets..."
aws secretsmanager delete-secret \
  --secret-id "$TEST_PREFIX-basic" \
  --force-delete-without-recovery || echo "Failed to delete basic secret"

echo "Local integration tests completed!"