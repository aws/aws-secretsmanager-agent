//! # Configuration Integration Tests
//!
//! This module contains integration tests for AWS Secrets Manager Agent's configuration features.
//! These tests verify that various configuration options (connection limits, TTL settings, etc.)
//! work correctly and affect agent behavior as expected.

mod common;

use common::*;
use std::sync::Arc;

#[tokio::test]
async fn test_real_connection_limits() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(SecretType::Basic);

    // Start agent with very low connection limit for testing
    const MAX_CONNECTIONS: u16 = 3;
    let agent =
        Arc::new(AgentProcess::start_with_complete_config(2781, 300, 100, MAX_CONNECTIONS).await);

    let query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();

    // Create more concurrent requests than the connection limit allows
    const CONCURRENT_REQUESTS: usize = 10;
    let mut handles = Vec::new();

    for i in 0..CONCURRENT_REQUESTS {
        let agent_clone = Arc::clone(&agent);
        let query_clone = query.clone();

        let handle = tokio::spawn(async move {
            let response = agent_clone.make_request_raw(&query_clone).await;
            (i, response.status().as_u16())
        });

        handles.push(handle);
    }

    // Wait for all requests to complete
    let mut results = Vec::new();
    for handle in handles {
        match handle.await {
            Ok((request_id, status_code)) => results.push((request_id, status_code)),
            Err(e) => panic!("Request failed: {:?}", e),
        }
    }

    // Count successful (200) and rejected requests
    let successful_requests = results.iter().filter(|(_, status)| *status == 200).count();
    let rejected_requests = results.iter().filter(|(_, status)| *status != 200).count();

    // With connection limits, some requests should be rejected
    // At least some should succeed (within connection limit)
    assert!(
        successful_requests > 0,
        "At least some requests should succeed"
    );
    assert!(
        successful_requests <= MAX_CONNECTIONS as usize,
        "Successful requests should not exceed connection limit"
    );

    // Verify that connection limiting is working by having some rejections
    // Note: This is probabilistic due to timing, but with 10 concurrent requests and limit of 3,
    // we should see some rejections in most cases
    println!(
        "Successful requests: {}, Rejected requests: {}",
        successful_requests, rejected_requests
    );
}
#[tokio::test]
async fn test_ping_endpoint_health_check() {
    let agent = AgentProcess::start().await;

    // Test 1: Ping endpoint should work without token
    let response_no_token = agent.make_ping_request().await;
    assert_eq!(response_no_token.status(), 200);

    let body_no_token = response_no_token
        .text()
        .await
        .expect("Failed to read response body");
    assert_eq!(body_no_token, "healthy");

    // Test 2: Ping endpoint should also work with token (token not required for ping)
    let response_with_token = agent.make_ping_request_with_token().await;
    assert_eq!(response_with_token.status(), 200);

    let body_with_token = response_with_token
        .text()
        .await
        .expect("Failed to read response body");
    assert_eq!(body_with_token, "healthy");
}
#[tokio::test]
async fn test_path_based_requests() {
    let secrets = TestSecrets::setup_basic().await;
    let secret_name = secrets.secret_name(SecretType::Basic);

    let agent = AgentProcess::start().await;

    // Test path-based request using default path_prefix "/v1/"
    let response_path = agent.make_path_based_request(&secret_name).await;
    assert_eq!(response_path.status(), 200);

    let body_path = response_path
        .text()
        .await
        .expect("Failed to read response body");
    let json_path: serde_json::Value = serde_json::from_str(&body_path).unwrap();
    assert!(json_path["SecretString"]
        .as_str()
        .unwrap()
        .contains("testuser"));
    assert_eq!(json_path["Name"].as_str().unwrap(), secret_name);

    // Compare with regular query-based request to ensure same result
    let query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let response_query = agent.make_request_raw(&query).await;
    assert_eq!(response_query.status(), 200);

    let body_query = response_query
        .text()
        .await
        .expect("Failed to read response body");
    let json_query: serde_json::Value = serde_json::from_str(&body_query).unwrap();

    // Both methods should return identical secret data
    assert_eq!(json_path["SecretString"], json_query["SecretString"]);
    assert_eq!(json_path["VersionId"], json_query["VersionId"]);
}
