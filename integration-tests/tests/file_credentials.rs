//! # File-Based Credentials Integration Tests
//!
//! Tests for the FileBasedCredentialsProvider feature, verifying the agent
//! correctly handles various credential file scenarios.
//!
//! **Note:** `test_self_healing_credentials_appear_after_startup` uses
//! `SMA_CREDENTIALS_RELOAD_SECS` and `test_credential_rotation_while_running`
//! uses both `SMA_CREDENTIALS_RELOAD_SECS` and `SMA_DISABLE_IDENTITY_CACHE`.
//! These env-var overrides are only active in debug builds of the agent binary.
//! These tests must be run against a debug build (`cargo build`, not
//! `cargo build --release`).

mod common;

use aws_credential_types::provider::ProvideCredentials;
use common::*;
use std::io::Write;
use tempfile::NamedTempFile;

/// Helper to write AWS credentials from the environment to a temp file.
/// Relies on the same credentials the existing integration tests use.
async fn write_real_credentials(file: &mut NamedTempFile) {
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let creds = config
        .credentials_provider()
        .expect("No credentials provider")
        .provide_credentials()
        .await
        .expect("Failed to resolve credentials");

    let mut content = format!(
        "[default]\naws_access_key_id={}\naws_secret_access_key={}\n",
        creds.access_key_id(),
        creds.secret_access_key()
    );
    if let Some(token) = creds.session_token() {
        content.push_str(&format!("aws_session_token={}\n", token));
    }
    file.write_all(content.as_bytes()).unwrap();
    file.flush().unwrap();
}

/// Valid credentials via explicit path: agent starts and can fetch a secret.
#[tokio::test]
async fn test_valid_credentials_explicit_path() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(SecretType::Basic);

    let mut creds_file = NamedTempFile::new().unwrap();
    write_real_credentials(&mut creds_file).await;

    let agent =
        AgentProcess::start_with_credentials_file(2785, Some(creds_file.path().to_str().unwrap()))
            .await;

    let query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let response = agent.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert_eq!(json["Name"], secret_name);
    assert!(json["SecretString"].as_str().unwrap().contains("testuser"));
}

/// Invalid credentials: agent starts but secret fetch returns auth error.
#[tokio::test]
async fn test_invalid_credentials_agent_starts() {
    let mut creds_file = NamedTempFile::new().unwrap();
    writeln!(
        creds_file,
        "[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\naws_session_token=FakeSessionToken"
    )
    .unwrap();

    let agent =
        AgentProcess::start_with_credentials_file(2786, Some(creds_file.path().to_str().unwrap()))
            .await;

    let query = AgentQueryBuilder::default()
        .secret_id("any-secret")
        .build()
        .unwrap();
    let response = agent.make_request_raw(&query).await;

    // Agent started (didn't crash), but request fails with auth error
    assert_ne!(response.status(), 200);
    let body = response.text().await.unwrap();
    assert!(!body.is_empty());
}

/// Malformed credentials file: agent starts, request returns InternalFailure.
#[tokio::test]
async fn test_malformed_credentials_file() {
    let mut creds_file = NamedTempFile::new().unwrap();
    writeln!(creds_file, "this is not a credentials file").unwrap();

    let agent =
        AgentProcess::start_with_credentials_file(2787, Some(creds_file.path().to_str().unwrap()))
            .await;

    let query = AgentQueryBuilder::default()
        .secret_id("any-secret")
        .build()
        .unwrap();
    let response = agent.make_request_raw(&query).await;

    assert_ne!(response.status(), 200);
    let body = response.text().await.unwrap();
    assert!(body.contains("InternalFailure"));
}

/// Empty credentials file: agent starts, request returns InternalFailure.
#[tokio::test]
async fn test_empty_credentials_file() {
    let creds_file = NamedTempFile::new().unwrap();

    let agent =
        AgentProcess::start_with_credentials_file(2788, Some(creds_file.path().to_str().unwrap()))
            .await;

    let query = AgentQueryBuilder::default()
        .secret_id("any-secret")
        .build()
        .unwrap();
    let response = agent.make_request_raw(&query).await;

    assert_ne!(response.status(), 200);
    let body = response.text().await.unwrap();
    assert!(body.contains("InternalFailure"));
}

/// Missing path: agent starts, request returns InternalFailure.
#[tokio::test]
async fn test_missing_credentials_path() {
    let agent =
        AgentProcess::start_with_credentials_file(2789, Some("/tmp/nonexistent_creds_file")).await;

    let query = AgentQueryBuilder::default()
        .secret_id("any-secret")
        .build()
        .unwrap();
    let response = agent.make_request_raw(&query).await;

    assert_ne!(response.status(), 200);
    let body = response.text().await.unwrap();
    assert!(body.contains("InternalFailure"));
}

/// Self-healing: agent starts with missing credentials, valid creds are written later,
/// agent picks them up on the next reload cycle.
#[tokio::test]
async fn test_self_healing_credentials_appear_after_startup() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(SecretType::Basic);

    let tmp_dir = tempfile::tempdir().unwrap();
    let creds_path = tmp_dir.path().join("credentials");

    // Start agent with a 5-second reload delay
    let agent = AgentProcess::start_with_credentials_file_and_env(
        2790,
        Some(creds_path.to_str().unwrap()),
        &[("SMA_CREDENTIALS_RELOAD_SECS", "5")],
    )
    .await;

    // First request should fail — no credentials yet
    let query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let response = agent.make_request_raw(&query).await;
    assert_ne!(response.status(), 200);

    // Write valid credentials to the file
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let creds = config
        .credentials_provider()
        .expect("No credentials provider")
        .provide_credentials()
        .await
        .expect("Failed to resolve credentials");

    let mut content = format!(
        "[default]\naws_access_key_id={}\naws_secret_access_key={}\n",
        creds.access_key_id(),
        creds.secret_access_key()
    );
    if let Some(token) = creds.session_token() {
        content.push_str(&format!("aws_session_token={}\n", token));
    }
    std::fs::write(&creds_path, content).unwrap();

    // Poll until the agent picks up the new credentials or timeout
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let resp = agent.make_request_raw(&query).await;
        if resp.status() == 200 {
            let body = resp.text().await.unwrap();
            let json: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(json["Name"], secret_name);
            assert!(json["SecretString"].as_str().unwrap().contains("testuser"));
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Timed out waiting for credentials reload"
        );
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/// Credential rotation: agent starts with valid credentials, credentials are invalidated,
/// agent fails, then valid credentials are restored and agent recovers.
/// This proves the agent is actively re-reading the file on each reload cycle.
/// Uses SMA_DISABLE_IDENTITY_CACHE to bypass the SDK's internal credential cache,
/// and refreshNow=true to bypass the secret value cache.
///
/// Note: A valid→valid→valid happy path test is not feasible because the test
/// environment only has one set of credentials (from the CI role). Rewriting the
/// same credentials to the file changes the mtime (triggering a reload) but the
/// credential values are identical, making it impossible to observe that the agent
/// actually swapped credentials. The valid→invalid→valid approach definitively
/// proves the reload by showing the agent fails with invalid credentials (proving
/// it stopped using the old cached ones) and recovers when valid credentials are
/// restored.
#[tokio::test]
async fn test_credential_rotation_while_running() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(SecretType::Basic);

    let tmp_dir = tempfile::tempdir().unwrap();
    let creds_path = tmp_dir.path().join("credentials");

    // Write initial valid credentials
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let creds = config
        .credentials_provider()
        .expect("No credentials provider")
        .provide_credentials()
        .await
        .expect("Failed to resolve credentials");

    let mut valid_content = format!(
        "[default]\naws_access_key_id={}\naws_secret_access_key={}\n",
        creds.access_key_id(),
        creds.secret_access_key()
    );
    if let Some(token) = creds.session_token() {
        valid_content.push_str(&format!("aws_session_token={}\n", token));
    }
    std::fs::write(&creds_path, &valid_content).unwrap();

    // Start agent with short reload delay and no identity cache
    let agent = AgentProcess::start_with_credentials_file_and_env(
        2792,
        Some(creds_path.to_str().unwrap()),
        &[
            ("SMA_CREDENTIALS_RELOAD_SECS", "3"),
            ("SMA_DISABLE_IDENTITY_CACHE", "1"),
        ],
    )
    .await;

    // Step 1: Verify agent works with initial valid credentials
    let query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let response = agent.make_request(&query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(json["Name"], secret_name);

    // Step 2: Overwrite with invalid credentials
    std::fs::write(
        &creds_path,
        "[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\naws_session_token=FakeSessionToken\n",
    )
    .unwrap();

    // Poll until agent returns errors (proves it picked up invalid creds)
    // Use refreshNow=true to bypass the secret value cache
    let refresh_query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .refresh_now(true)
        .build()
        .unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let resp = agent.make_request_raw(&refresh_query).await;
        if resp.status() != 200 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Timed out waiting for agent to pick up invalid credentials"
        );
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    // Step 3: Restore valid credentials
    std::fs::write(&creds_path, &valid_content).unwrap();

    // Poll until agent recovers
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let resp = agent.make_request_raw(&refresh_query).await;
        if resp.status() == 200 {
            let body = resp.text().await.unwrap();
            let json: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(json["Name"], secret_name);
            assert!(json["SecretString"].as_str().unwrap().contains("testuser"));
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Timed out waiting for agent to recover with valid credentials"
        );
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
