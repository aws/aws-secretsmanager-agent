mod common;

use common::*;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_stale_cache_during_secret_update() {
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

    // Update the secret in AWS (simulating manual update, not automatic rotation)
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    let updated_secret_value = r#"{"username":"rotateduser","password":"rotatedpass123"}"#;
    client
        .update_secret()
        .secret_id(&secret_name)
        .secret_string(updated_secret_value)
        .send()
        .await
        .expect("Failed to update secret");

    // Wait for the update to propagate
    sleep(Duration::from_secs(2)).await;

    // Second request without refreshNow - should return stale cached value
    let response2 = agent.make_request(&query).await;
    let json2: serde_json::Value = serde_json::from_str(&response2).unwrap();
    let cached_secret = json2["SecretString"].as_str().unwrap();

    // Should still have the old value from cache
    assert!(cached_secret.contains("testuser"));
    assert!(!cached_secret.contains("rotateduser"));

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
    assert!(fresh_secret.contains("rotateduser"));
    assert!(!fresh_secret.contains("testuser"));
}

#[tokio::test]
async fn test_cache_expiration_and_refresh() {
    let secrets = TestSecrets::setup().await;
    let secret_name = secrets.secret_name(SecretType::Basic);

    // Start agent with short TTL (5 seconds) for faster testing
    let agent = AgentProcess::start_with_config(2777, 5).await;

    let query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();

    // First request - populate cache
    let response1 = agent.make_request(&query).await;
    let json1: serde_json::Value = serde_json::from_str(&response1).unwrap();
    let version1 = json1["VersionId"].as_str().unwrap();
    assert!(json1["SecretString"].as_str().unwrap().contains("testuser"));

    // Second request immediately - should hit cache (same version)
    let response2 = agent.make_request(&query).await;
    let json2: serde_json::Value = serde_json::from_str(&response2).unwrap();
    assert_eq!(json1["VersionId"], json2["VersionId"]);

    // Update secret while cache is still valid
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);
    
    client
        .update_secret()
        .secret_id(&secret_name)
        .secret_string(r#"{"username":"expireduser","password":"expiredpass789"}"#)
        .send()
        .await
        .expect("Failed to update secret");

    // Wait for update to propagate
    sleep(Duration::from_secs(2)).await;

    // Third request before TTL expires - should still return cached value
    let response3 = agent.make_request(&query).await;
    let json3: serde_json::Value = serde_json::from_str(&response3).unwrap();
    assert_eq!(json3["VersionId"], version1); // Same version as cached
    assert!(json3["SecretString"].as_str().unwrap().contains("testuser"));

    // Wait for TTL to expire (5 seconds + buffer)
    sleep(Duration::from_secs(4)).await;

    // Fourth request after TTL expiry - should fetch fresh value from AWS
    let response4 = agent.make_request(&query).await;
    let json4: serde_json::Value = serde_json::from_str(&response4).unwrap();
    
    // Should now have the updated value and different version
    assert_ne!(json4["VersionId"], version1);
    assert!(json4["SecretString"].as_str().unwrap().contains("expireduser"));
    assert!(!json4["SecretString"].as_str().unwrap().contains("testuser"));

    // Fifth request immediately after - should use newly cached value
    let response5 = agent.make_request(&query).await;
    let json5: serde_json::Value = serde_json::from_str(&response5).unwrap();
    assert_eq!(json4["VersionId"], json5["VersionId"]); // Same as previous
    assert!(json5["SecretString"].as_str().unwrap().contains("expireduser"));
}

