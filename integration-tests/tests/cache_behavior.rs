mod common;

use common::*;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_refresh_now_on_updated_secret_succeeds() {
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
    let update_response = client
        .update_secret()
        .secret_id(&secret_name)
        .secret_string(updated_secret_value)
        .send()
        .await
        .expect("Failed to update secret");
    
    let new_version_id = update_response.version_id().expect("No version ID returned");

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

    // Should now have the updated value with new version ID and AWSCURRENT label
    assert_eq!(json3["VersionId"].as_str().unwrap(), new_version_id);
    assert!(json3["VersionStages"].as_array().unwrap().contains(&serde_json::Value::String("AWSCURRENT".to_string())));
    assert!(fresh_secret.contains("rotateduser"));
    assert!(!fresh_secret.contains("testuser"));
}

#[tokio::test]
async fn test_cache_expiration_and_refresh() {
    let secrets = TestSecrets::setup().await;
    let secret_name = secrets.secret_name(SecretType::Basic);

    // Start agent with short TTL for faster testing
    const TTL_SECONDS: u16 = 5;
    let agent = AgentProcess::start_with_config(2777, TTL_SECONDS).await;

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

    let update_response = client
        .update_secret()
        .secret_id(&secret_name)
        .secret_string(r#"{"username":"expireduser","password":"expiredpass789"}"#)
        .send()
        .await
        .expect("Failed to update secret");
    
    let new_version_id = update_response.version_id().expect("No version ID returned");

    // Third request before TTL expires - should still return cached value
    let response3 = agent.make_request(&query).await;
    let json3: serde_json::Value = serde_json::from_str(&response3).unwrap();
    assert_eq!(json3["VersionId"], version1); // Same version as cached
    assert!(json3["SecretString"].as_str().unwrap().contains("testuser"));

    // Wait for TTL to expire (TTL + buffer to ensure expiry)
    sleep(Duration::from_secs(TTL_SECONDS as u64 + 1)).await;

    // Fourth request after TTL expiry - should fetch fresh value from AWS
    let response4 = agent.make_request(&query).await;
    let json4: serde_json::Value = serde_json::from_str(&response4).unwrap();

    // Should now have the updated value with new version ID and AWSCURRENT label
    assert_eq!(json4["VersionId"].as_str().unwrap(), new_version_id);
    assert!(json4["VersionStages"].as_array().unwrap().contains(&serde_json::Value::String("AWSCURRENT".to_string())));
    assert!(json4["SecretString"]
        .as_str()
        .unwrap()
        .contains("expireduser"));
    assert!(!json4["SecretString"].as_str().unwrap().contains("testuser"));

    // Fifth request immediately after - should use newly cached value
    let response5 = agent.make_request(&query).await;
    let json5: serde_json::Value = serde_json::from_str(&response5).unwrap();
    assert_eq!(json4["VersionId"], json5["VersionId"]); // Same as previous
    assert!(json5["SecretString"]
        .as_str()
        .unwrap()
        .contains("expireduser"));
}
