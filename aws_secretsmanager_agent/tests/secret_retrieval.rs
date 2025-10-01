mod common;

use common::*;

#[tokio::test]
#[ignore = "integration test - requires TEST_SECRET_PREFIX env var and AWS credentials"]
async fn test_secret_retrieval_by_name() {
    let secret_prefix = get_test_secret_prefix();
    let secret_name = format!("{}-basic", secret_prefix);
    
    let agent = start_agent_on_port(2775).await;
    
    let response = make_agent_request(agent.port, &format!("secretId={}", secret_name)).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();
    
    assert_eq!(json["Name"], secret_name);
    assert!(json["SecretString"].as_str().unwrap().contains("testuser"));
    assert!(json["VersionId"].is_string());
}

#[tokio::test]
#[ignore = "integration test - requires TEST_SECRET_PREFIX env var and AWS credentials"]
async fn test_secret_retrieval_by_arn() {
    let secret_prefix = get_test_secret_prefix();
    let secret_name = format!("{}-basic", secret_prefix);
    
    // Get the ARN first
    let output = std::process::Command::new("aws")
        .args(&["secretsmanager", "describe-secret", "--secret-id", &secret_name])
        .output()
        .expect("Failed to describe secret");
    
    let describe_response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let arn = describe_response["ARN"].as_str().unwrap();
    
    let agent = start_agent_on_port(2776).await;
    
    let response = make_agent_request(agent.port, &format!("secretId={}", arn)).await;
    let json: serde_json::Value = serde_json::from_str(&response).unwrap();
    
    assert_eq!(json["ARN"], arn);
    assert!(json["SecretString"].as_str().unwrap().contains("testuser"));
}