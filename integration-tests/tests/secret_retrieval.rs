mod common;

use common::*;

#[tokio::test]
#[ignore = "integration test - requires AWS credentials"]
async fn test_secret_retrieval_by_name() {
    let secret_prefix = setup_test_secrets().await;
    let secret_name = format!("{}-basic", secret_prefix);

    let agent = start_agent_on_port(2775).await;

    let query = AgentQuery::new(&secret_name);
    let response = make_agent_request(agent.port, &query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert_eq!(json["Name"], secret_name);
    assert!(json["SecretString"].as_str().unwrap().contains("testuser"));
    assert!(json["VersionId"].is_string());

    cleanup_test_secrets(&secret_prefix).await;
}

#[tokio::test]
#[ignore = "integration test - requires AWS credentials"]
async fn test_secret_retrieval_by_arn() {
    let secret_prefix = setup_test_secrets().await;
    let secret_name = format!("{}-basic", secret_prefix);

    // Get the ARN using AWS SDK
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    let describe_response = client
        .describe_secret()
        .secret_id(&secret_name)
        .send()
        .await
        .expect("Failed to describe secret");

    let arn = describe_response.arn().expect("Secret ARN not found");

    let agent = start_agent_on_port(2776).await;

    let query = AgentQuery::new(arn);
    let response = make_agent_request(agent.port, &query).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();

    assert_eq!(json["ARN"], arn);
    assert!(json["SecretString"].as_str().unwrap().contains("testuser"));

    cleanup_test_secrets(&secret_prefix).await;
}
