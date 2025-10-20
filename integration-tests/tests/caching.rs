mod common;

use common::*;
use std::time::{Duration, Instant};

#[tokio::test]
async fn test_cache_hit_behavior() {
    let secrets = TestSecrets::setup().await;
    let secret_name = secrets.secret_name(SecretType::Basic);

    let agent = AgentProcess::start().await;

    // First request - should fetch from AWS and cache
    let query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();

    let start_time = Instant::now();
    let response1 = agent.make_request(&query).await;
    let first_request_duration = start_time.elapsed();

    let json1: serde_json::Value = serde_json::from_str(&response1).unwrap();
    assert_eq!(json1["Name"], secret_name);
    assert!(json1["SecretString"].as_str().unwrap().contains("testuser"));

    // Second request - should be served from cache (much faster)
    let start_time = Instant::now();
    let response2 = agent.make_request(&query).await;
    let second_request_duration = start_time.elapsed();

    let json2: serde_json::Value = serde_json::from_str(&response2).unwrap();
    assert_eq!(json2["Name"], secret_name);
    assert!(json2["SecretString"].as_str().unwrap().contains("testuser"));

    // Verify responses are identical (from cache)
    assert_eq!(json1["VersionId"], json2["VersionId"]);
    assert_eq!(json1["SecretString"], json2["SecretString"]);

    // Cache hit should be significantly faster than initial AWS call
    // Allow some tolerance for timing variations
    assert!(
        second_request_duration < first_request_duration / 2,
        "Cache hit should be faster. First: {:?}, Second: {:?}",
        first_request_duration,
        second_request_duration
    );
}

#[tokio::test]
async fn test_refresh_now_bypasses_cache() {
    let secrets = TestSecrets::setup().await;
    let secret_name = secrets.secret_name(SecretType::Basic);

    let agent = AgentProcess::start().await;

    // First request - populate cache
    let query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let response1 = agent.make_request(&query).await;
    let _json1: serde_json::Value = serde_json::from_str(&response1).unwrap();

    // Second request with refreshNow=true - should bypass cache
    let refresh_query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .refresh_now(true)
        .build()
        .unwrap();

    let start_time = Instant::now();
    let response2 = agent.make_request(&refresh_query).await;
    let refresh_duration = start_time.elapsed();

    let json2: serde_json::Value = serde_json::from_str(&response2).unwrap();

    // Verify we got a valid response
    assert_eq!(json2["Name"], secret_name);
    assert!(json2["SecretString"].as_str().unwrap().contains("testuser"));

    // refreshNow should take longer than a cache hit (it goes to AWS)
    // This is a network call, so should be measurably slower than cache
    assert!(
        refresh_duration > Duration::from_millis(10),
        "refreshNow should make AWS call, duration: {:?}",
        refresh_duration
    );

    // Third request without refreshNow - should use updated cache
    let response3 = agent.make_request(&query).await;
    let json3: serde_json::Value = serde_json::from_str(&response3).unwrap();

    assert_eq!(json3["Name"], secret_name);
    assert!(json3["SecretString"].as_str().unwrap().contains("testuser"));
}

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
    let start_time = Instant::now();
    let response1 = agent.make_request(&query).await;
    let first_duration = start_time.elapsed();
    let json1: serde_json::Value = serde_json::from_str(&response1).unwrap();
    assert!(json1["SecretString"].as_str().unwrap().contains("testuser"));

    // Second request immediately - should hit cache (fast)
    let start_time = Instant::now();
    let response2 = agent.make_request(&query).await;
    let cache_hit_duration = start_time.elapsed();
    let json2: serde_json::Value = serde_json::from_str(&response2).unwrap();

    // Verify cache hit is faster
    assert!(cache_hit_duration < first_duration / 2);
    assert_eq!(json1["VersionId"], json2["VersionId"]);

    // Wait for TTL to expire (3 seconds + buffer)
    tokio::time::sleep(Duration::from_secs(4)).await;

    // Third request after TTL expiry - should fetch from AWS again (slower)
    let start_time = Instant::now();
    let response3 = agent.make_request(&query).await;
    let post_ttl_duration = start_time.elapsed();
    let json3: serde_json::Value = serde_json::from_str(&response3).unwrap();

    // Post-TTL request should be slower than cache hit (goes to AWS)
    assert!(
        post_ttl_duration > cache_hit_duration * 2,
        "Post-TTL request should be slower. Cache hit: {:?}, Post-TTL: {:?}",
        cache_hit_duration,
        post_ttl_duration
    );

    // Should still get valid response
    assert!(json3["SecretString"].as_str().unwrap().contains("testuser"));
}

#[tokio::test]
async fn test_ttl_zero_disables_caching() {
    let secrets = TestSecrets::setup().await;
    let secret_name = secrets.secret_name(SecretType::Basic);

    // Start agent with TTL=0 to disable caching
    let agent = AgentProcess::start_with_config(2775, 0).await;

    let query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();

    // Make multiple requests and verify they all take significant time (go to AWS)
    let mut durations = Vec::new();

    for i in 0..4 {
        let start_time = Instant::now();
        let response = agent.make_request(&query).await;
        let duration = start_time.elapsed();
        durations.push(duration);

        let json: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert!(json["SecretString"].as_str().unwrap().contains("testuser"));

        // Each request should take significant time (network call to AWS)
        assert!(
            duration > Duration::from_millis(20),
            "Request {} should go to AWS with TTL=0, duration: {:?}",
            i + 1,
            duration
        );

        // Small delay between requests to avoid overwhelming AWS
        if i < 3 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    // Verify no request was significantly faster (indicating cache hit)
    let min_duration = durations.iter().min().unwrap();

    // All requests should be in reasonable range (no cache speedup)
    // Allow for network variance but ensure no sub-15ms cache hits
    assert!(
        min_duration > &Duration::from_millis(15),
        "Minimum duration too fast, suggests caching: {:?}. All durations: {:?}",
        min_duration,
        durations
    );
}
