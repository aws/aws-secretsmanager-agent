mod common;

use common::*;

#[tokio::test]
async fn test_cross_account_secret_access() {
    let secrets = TestSecrets::setup().await;
    let secret_name = secrets.secret_name(SecretType::Basic);

    let agent = AgentProcess::start().await;

    // Get the ARN of the secret for cross-account testing
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    let describe_response = client
        .describe_secret()
        .secret_id(&secret_name)
        .send()
        .await
        .expect("Failed to describe secret");

    let secret_arn = describe_response.arn().expect("Secret ARN not found");

    // Test accessing secret by ARN (simulates cross-account access pattern)
    let arn_query = AgentQueryBuilder::default()
        .secret_id(secret_arn)
        .build()
        .unwrap();
    let arn_response = agent.make_request(&arn_query).await;
    let arn_json: serde_json::Value = serde_json::from_str(&arn_response).unwrap();

    // Verify the response contains the correct data
    assert_eq!(arn_json["ARN"], secret_arn);
    assert_eq!(arn_json["Name"], secret_name);
    assert!(arn_json["SecretString"]
        .as_str()
        .unwrap()
        .contains("testuser"));
    assert!(arn_json["VersionId"].is_string());

    // Test accessing secret by name (same account pattern)
    let name_query = AgentQueryBuilder::default()
        .secret_id(&secret_name)
        .build()
        .unwrap();
    let name_response = agent.make_request(&name_query).await;
    let name_json: serde_json::Value = serde_json::from_str(&name_response).unwrap();

    // Both responses should contain the same secret data
    assert_eq!(arn_json["VersionId"], name_json["VersionId"]);
    assert_eq!(arn_json["SecretString"], name_json["SecretString"]);
    assert_eq!(arn_json["CreatedDate"], name_json["CreatedDate"]);

    // Test that ARN-based access works with version stages
    let arn_version_query = AgentQueryBuilder::default()
        .secret_id(secret_arn)
        .version_stage("AWSCURRENT")
        .build()
        .unwrap();
    let arn_version_response = agent.make_request(&arn_version_query).await;
    let arn_version_json: serde_json::Value = serde_json::from_str(&arn_version_response).unwrap();

    assert_eq!(arn_version_json["ARN"], secret_arn);
    assert!(arn_version_json["VersionStages"]
        .as_array()
        .unwrap()
        .contains(&serde_json::Value::String("AWSCURRENT".to_string())));

    // Test that ARN-based access works with refreshNow
    let arn_refresh_query = AgentQueryBuilder::default()
        .secret_id(secret_arn)
        .refresh_now(true)
        .build()
        .unwrap();
    let arn_refresh_response = agent.make_request(&arn_refresh_query).await;
    let arn_refresh_json: serde_json::Value = serde_json::from_str(&arn_refresh_response).unwrap();

    assert_eq!(arn_refresh_json["ARN"], secret_arn);
    assert_eq!(arn_refresh_json["VersionId"], arn_json["VersionId"]);
}