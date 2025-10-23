# Test Labeling Gate

This is a test file to verify the GitHub Actions labeling gate works correctly.

## Expected Behavior

1. PR created without `safe-to-test` label → No integration tests run
2. Add `safe-to-test` label → Integration tests trigger
3. Label automatically removed after test execution

## Security Verification

This ensures no unauthorized code can execute with AWS credentials without explicit human approval.