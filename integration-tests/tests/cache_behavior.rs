//! # Cache Behavior Integration Tests
//!
//! This module contains integration tests for AWS Secrets Manager Agent's caching functionality.
//! These tests verify that the agent correctly caches secrets, respects TTL settings, handles
//! cache refresh scenarios including the refreshNow parameter, validates cache size limits,
//! and ensures thread-safe concurrent access to cached secrets.

mod common;

use common::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_refresh_now_on_updated_secret_succeeds() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name: String = secrets.secret_name(SecretType::Basic);

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

    let new_version_id = update_response
        .version_id()
        .expect("No version ID returned");

    // Allow time for update to propagate across Secrets Manager nodes
    sleep(Duration::from_millis(500)).await;

    // Second request without refreshNow - should return stale cached value
    let response2 = agent.make_request(&query).await;
    let json2: serde_json::Value = serde_json::from_str(&response2).unwrap();
    let cached_secret = json2["SecretString"].as_str().unwrap();

    // Should still have the old value from cache
    assert!(cached_secret.contains("testuser"));

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
    assert!(json3["VersionStages"]
        .as_array()
        .unwrap()
        .contains(&serde_json::Value::String("AWSCURRENT".to_string())));
    assert!(fresh_secret.contains("rotateduser"));
}

#[tokio::test]
async fn test_cache_expiration_and_refresh() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(SecretType::Basic);

    // Start agent with short TTL for faster testing
    const TTL_SECONDS: u64 = 5;
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

    let new_version_id = update_response
        .version_id()
        .expect("No version ID returned");

    // Allow time for update to propagate across Secrets Manager nodes
    sleep(Duration::from_millis(500)).await;

    // Second request before TTL expires - should still return cached value
    let response2 = agent.make_request(&query).await;
    let json2: serde_json::Value = serde_json::from_str(&response2).unwrap();
    assert_eq!(json2["VersionId"], version1); // Same version as cached
    assert!(json2["SecretString"].as_str().unwrap().contains("testuser"));

    // Wait for TTL to expire (TTL + buffer to ensure expiry)
    sleep(Duration::from_secs(TTL_SECONDS + 1)).await;

    // Third request after TTL expiry - should fetch fresh value from AWS
    let response3 = agent.make_request(&query).await;
    let json3: serde_json::Value = serde_json::from_str(&response3).unwrap();

    // Should now have the updated value with new version ID and AWSCURRENT label
    assert_eq!(json3["VersionId"].as_str().unwrap(), new_version_id);
    assert!(json3["VersionStages"]
        .as_array()
        .unwrap()
        .contains(&serde_json::Value::String("AWSCURRENT".to_string())));
    assert!(json3["SecretString"]
        .as_str()
        .unwrap()
        .contains("expireduser"));
}

#[tokio::test]
async fn test_cache_size_limits_with_real_memory() {
    // Test with a small cache size to validate eviction behavior
    const CACHE_SIZE: u16 = 3;
    const TTL_SECONDS: u64 = 300; // Long TTL to ensure cache eviction, not expiration

    // Create multiple secrets to exceed cache limit
    let secrets = TestSecrets::setup_basic().await;
    let base_secret_name = secrets.secret_name(SecretType::Basic);

    // Create additional test secrets by updating the base secret with different content
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    // Create unique secret names for cache testing
    let mut secret_names = vec![base_secret_name.clone()];

    // Create 2 more secrets by creating new ones (total of 3 to fill cache)
    for i in 1..=2 {
        let additional_secret_name = format!("{}-cache-test-{}", base_secret_name, i);
        client
            .create_secret()
            .name(&additional_secret_name)
            .description("Cache size test secret")
            .secret_string(&format!(
                r#"{{"username":"cacheuser{}","password":"cachepass{}"}}"#,
                i, i
            ))
            .send()
            .await
            .expect("Failed to create additional test secret");
        secret_names.push(additional_secret_name);
    }

    // Start agent with limited cache size
    let agent = AgentProcess::start_with_full_config(2778, TTL_SECONDS, CACHE_SIZE).await;

    // Fill the cache to capacity (3 secrets)
    for (i, secret_name) in secret_names.iter().enumerate() {
        let query = AgentQueryBuilder::default()
            .secret_id(secret_name)
            .build()
            .unwrap();
        let response = agent.make_request(&query).await;
        let json: serde_json::Value = serde_json::from_str(&response).unwrap();

        if i == 0 {
            assert!(json["SecretString"].as_str().unwrap().contains("testuser"));
        } else {
            assert!(json["SecretString"]
                .as_str()
                .unwrap()
                .contains(&format!("cacheuser{}", i)));
        }
    }

    // Create and request a 4th secret - this should trigger cache eviction
    let eviction_secret_name = format!("{}-eviction-test", base_secret_name);
    client
        .create_secret()
        .name(&eviction_secret_name)
        .description("Cache eviction test secret")
        .secret_string(r#"{"username":"evictionuser","password":"evictionpass"}"#)
        .send()
        .await
        .expect("Failed to create eviction test secret");

    // Request the 4th secret - should evict the oldest cached secret
    let eviction_query = AgentQueryBuilder::default()
        .secret_id(&eviction_secret_name)
        .build()
        .unwrap();
    let eviction_response = agent.make_request(&eviction_query).await;
    let eviction_json: serde_json::Value = serde_json::from_str(&eviction_response).unwrap();
    assert!(eviction_json["SecretString"]
        .as_str()
        .unwrap()
        .contains("evictionuser"));

    // Verify cache still works for recently accessed secrets
    // The most recently accessed secrets should still be cached
    let recent_query = AgentQueryBuilder::default()
        .secret_id(&secret_names[2]) // Last secret we accessed before eviction
        .build()
        .unwrap();
    let recent_response = agent.make_request(&recent_query).await;
    let recent_json: serde_json::Value = serde_json::from_str(&recent_response).unwrap();
    assert!(recent_json["SecretString"]
        .as_str()
        .unwrap()
        .contains("cacheuser2"));

    // Clean up additional secrets
    for secret_name in &secret_names[1..] {
        let _ = client
            .delete_secret()
            .secret_id(secret_name)
            .force_delete_without_recovery(true)
            .send()
            .await;
    }
    let _ = client
        .delete_secret()
        .secret_id(&eviction_secret_name)
        .force_delete_without_recovery(true)
        .send()
        .await;
}

#[tokio::test]
async fn test_concurrent_cache_access_real_secrets() {
    // Test concurrent access to validate cache thread-safety
    const CONCURRENT_REQUESTS: usize = 20;
    const TTL_SECONDS: u64 = 300; // Long TTL to ensure we're testing cache, not AWS calls

    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(SecretType::Basic);

    // Start agent with default cache size
    let agent = Arc::new(AgentProcess::start_with_config(2779, TTL_SECONDS).await);

    // Pre-populate cache with initial request
    let initial_query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let initial_response = agent.make_request(&initial_query).await;
    let initial_json: serde_json::Value = serde_json::from_str(&initial_response).unwrap();
    let expected_version_id = initial_json["VersionId"].as_str().unwrap();
    assert!(initial_json["SecretString"]
        .as_str()
        .unwrap()
        .contains("testuser"));

    // Create multiple concurrent tasks that access the same cached secret
    let mut handles = Vec::new();

    for i in 0..CONCURRENT_REQUESTS {
        let agent_clone = Arc::clone(&agent);
        let secret_name_clone = secret_name.clone();
        let expected_version_clone = expected_version_id.to_string();

        let handle = tokio::spawn(async move {
            // Each task makes multiple requests to stress-test cache concurrency
            for request_num in 0..3 {
                let query = AgentQueryBuilder::default()
                    .secret_id(&secret_name_clone)
                    .build()
                    .unwrap();

                let response = agent_clone.make_request(&query).await;
                let json: serde_json::Value = serde_json::from_str(&response).expect(&format!(
                    "Failed to parse JSON in task {} request {}",
                    i, request_num
                ));

                // Validate response consistency across concurrent requests
                assert_eq!(
                    json["VersionId"].as_str().unwrap(),
                    expected_version_clone,
                    "Version ID mismatch in task {} request {}",
                    i,
                    request_num
                );

                assert!(
                    json["SecretString"].as_str().unwrap().contains("testuser"),
                    "Secret content mismatch in task {} request {}",
                    i,
                    request_num
                );

                assert_eq!(
                    json["Name"].as_str().unwrap(),
                    secret_name_clone,
                    "Secret name mismatch in task {} request {}",
                    i,
                    request_num
                );

                // Small delay to create more realistic concurrent access patterns
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            // Return task completion indicator
            format!("Task {} completed", i)
        });

        handles.push(handle);
    }

    // Wait for all concurrent tasks to complete
    for (i, handle) in handles.into_iter().enumerate() {
        match handle.await {
            Ok(completion_msg) => {
                assert_eq!(completion_msg, format!("Task {} completed", i));
            }
            Err(e) => {
                panic!("Task {} failed with error: {:?}", i, e);
            }
        }
    }

    // Final verification: cache should still be functional after concurrent stress
    let final_query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let final_response = agent.make_request(&final_query).await;
    let final_json: serde_json::Value = serde_json::from_str(&final_response).unwrap();

    assert_eq!(
        final_json["VersionId"].as_str().unwrap(),
        expected_version_id
    );
    assert!(final_json["SecretString"]
        .as_str()
        .unwrap()
        .contains("testuser"));

    // Test concurrent access with refreshNow to stress cache invalidation paths
    let mut refresh_handles = Vec::new();

    for i in 0..5 {
        let agent_clone = Arc::clone(&agent);
        let secret_name_clone = secret_name.clone();

        let refresh_handle = tokio::spawn(async move {
            let refresh_query = AgentQueryBuilder::default()
                .secret_id(&secret_name_clone)
                .refresh_now(true)
                .build()
                .unwrap();

            let response = agent_clone.make_request(&refresh_query).await;
            let json: serde_json::Value = serde_json::from_str(&response)
                .expect(&format!("Failed to parse refresh JSON in task {}", i));

            // All refresh requests should return consistent data
            assert!(json["SecretString"].as_str().unwrap().contains("testuser"));
            json["VersionId"].as_str().unwrap().to_string()
        });

        refresh_handles.push(refresh_handle);
    }

    // Wait for all refresh tasks and verify consistency
    let mut refresh_results = Vec::new();
    for handle in refresh_handles {
        match handle.await {
            Ok(version_id) => refresh_results.push(version_id),
            Err(e) => panic!("Refresh task failed with error: {:?}", e),
        }
    }

    // Verify all refresh tasks returned consistent version IDs
    let first_version = &refresh_results[0];
    for (i, version_id) in refresh_results.iter().enumerate() {
        assert_eq!(
            version_id, first_version,
            "Inconsistent version ID in concurrent refresh task {}",
            i
        );
    }
}
#[tokio::test]
async fn test_ttl_zero_disables_caching() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(SecretType::Basic);

    // Start agent with TTL=0 to disable caching
    const TTL_SECONDS: u64 = 0;
    let agent = AgentProcess::start_with_config(2780, TTL_SECONDS).await;

    let query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();

    // First request - should fetch from AWS
    let response1 = agent.make_request(&query).await;
    let json1: serde_json::Value = serde_json::from_str(&response1).unwrap();
    let version1 = json1["VersionId"].as_str().unwrap();
    assert!(json1["SecretString"].as_str().unwrap().contains("testuser"));

    // Update secret immediately
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    let update_response = client
        .update_secret()
        .secret_id(&secret_name)
        .secret_string(r#"{"username":"nocacheuser","password":"nocachepass456"}"#)
        .send()
        .await
        .expect("Failed to update secret");

    let new_version_id = update_response
        .version_id()
        .expect("No version ID returned");

    // Allow time for update to propagate
    sleep(Duration::from_millis(500)).await;

    // Second request - with TTL=0, should always fetch fresh value from AWS
    let response2 = agent.make_request(&query).await;
    let json2: serde_json::Value = serde_json::from_str(&response2).unwrap();

    // Should immediately have the updated value (no caching)
    assert_eq!(json2["VersionId"].as_str().unwrap(), new_version_id);
    assert!(json2["VersionStages"]
        .as_array()
        .unwrap()
        .contains(&serde_json::Value::String("AWSCURRENT".to_string())));
    assert!(json2["SecretString"]
        .as_str()
        .unwrap()
        .contains("nocacheuser"));

    // Verify version changed (proving no caching occurred)
    assert_ne!(version1, new_version_id);
}
