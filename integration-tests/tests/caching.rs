mod common;

use common::*;
use std::time::Duration;

#[tokio::test]
async fn test_cache_after_secret_update() {
    let secrets = TestSecrets::setup().await;
    let secret_name = secrets.secret_name(SecretType::Basic);

    let agent = AgentProcess::start().await;

    // First request - populate cache with original value
    let query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let response1 = agent.make_request(&query).await;
    let json1: serde_json::Value = serde_json::from_str(&response1).unwrap();
    let original_secret = json1["SecretString"].as_str().unwrap();
    assert!(original_secret.contains("testuser"));

    // Update the secret in AWS
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    let updated_secret_value = r#"{"username":"updateduser","password":"updatedpass456"}"#;
    client
        .update_secret()
        .secret_id(&secret_name)
        .secret_string(updated_secret_value)
        .send()
        .await
        .expect("Failed to update secret");

    // Wait a moment for the update to propagate
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Second request without refreshNow - should return stale cached value
    let response2 = agent.make_request(&query).await;
    let json2: serde_json::Value = serde_json::from_str(&response2).unwrap();
    let cached_secret = json2["SecretString"].as_str().unwrap();

    // Should still have the old value from cache
    assert!(cached_secret.contains("testuser"));
    assert!(!cached_secret.contains("updateduser"));

    // Third request with refreshNow=true - should get fresh value
    let refresh_query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .refresh_now(true)
        .build()
        .unwrap();
    let response3 = agent.make_request(&refresh_query).await;
    let json3: serde_json::Value = serde_json::from_str(&response3).unwrap();
    let fresh_secret = json3["SecretString"].as_str().unwrap();

    // Should now have the updated value
    assert!(fresh_secret.contains("updateduser"));
    assert!(!fresh_secret.contains("testuser"));

    // Fourth request without refreshNow - cache should now have updated value
    let response4 = agent.make_request(&query).await;
    let json4: serde_json::Value = serde_json::from_str(&response4).unwrap();
    let updated_cached_secret = json4["SecretString"].as_str().unwrap();

    // Cache should now contain the updated value
    assert!(updated_cached_secret.contains("updateduser"));
    assert!(!updated_cached_secret.contains("testuser"));
}

#[tokio::test]
async fn test_real_ttl_expiration_timing() {
    let secrets = TestSecrets::setup().await;
    let secret_name = secrets.secret_name(SecretType::Basic);

    // Start agent with short TTL (3 seconds) for faster testing
    let agent = AgentProcess::start_with_config(2775, 3).await;

    let query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();

    // First request - populate cache
    let response1 = agent.make_request(&query).await;
    let json1: serde_json::Value = serde_json::from_str(&response1).unwrap();
    assert!(json1["SecretString"].as_str().unwrap().contains("testuser"));

    // Second request immediately - should hit cache
    let response2 = agent.make_request(&query).await;
    let json2: serde_json::Value = serde_json::from_str(&response2).unwrap();
    assert_eq!(json1["VersionId"], json2["VersionId"]);

    // Wait for TTL to expire (3 seconds + buffer)
    tokio::time::sleep(Duration::from_secs(4)).await;

    // Third request after TTL expiry - should fetch from AWS again
    let response3 = agent.make_request(&query).await;
    let json3: serde_json::Value = serde_json::from_str(&response3).unwrap();

    // Should still get valid response after TTL expiry
    assert!(json3["SecretString"].as_str().unwrap().contains("testuser"));
}
