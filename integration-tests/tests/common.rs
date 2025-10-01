use aws_config;
use aws_sdk_secretsmanager;
use derive_builder::Builder;
use std::env;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as TokioCommand;
use url::Url;

#[derive(Debug, Builder)]
#[builder(setter(into, strip_option))]
pub struct AgentQuery {
    pub secret_id: String,
    #[builder(default)]
    pub version_id: Option<String>,
    #[builder(default)]
    pub version_stage: Option<String>,
    #[builder(default)]
    pub refresh_now: Option<bool>,
}

impl AgentQuery {
    pub fn to_query_string(&self) -> String {
        let mut url = Url::parse("http://localhost/").unwrap();
        {
            let mut query_pairs = url.query_pairs_mut();
            query_pairs.append_pair("secretId", &self.secret_id);

            if let Some(version_id) = &self.version_id {
                query_pairs.append_pair("versionId", version_id);
            }

            if let Some(version_stage) = &self.version_stage {
                query_pairs.append_pair("versionStage", version_stage);
            }

            if let Some(refresh_now) = self.refresh_now {
                query_pairs.append_pair("refreshNow", &refresh_now.to_string());
            }
        }
        url.query().unwrap_or("").to_string()
    }
}

pub struct AgentProcess {
    pub child: tokio::process::Child,
    pub port: u16,
}

impl Drop for AgentProcess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

pub async fn start_agent_on_port(port: u16) -> AgentProcess {
    let config_content = format!(
        r#"
http_port = {}
log_level = "info"
ttl_seconds = 5
cache_size = 100
validate_credentials = false
"#,
        port
    );

    let config_path = format!("/tmp/test_config_{}.toml", port);
    std::fs::write(&config_path, config_content).expect("Failed to write test config");

    env::set_var("AWS_TOKEN", "test-token-123");

    let possible_paths = [
        PathBuf::from("target")
            .join("release")
            .join("aws_secretsmanager_agent"),
        PathBuf::from("target")
            .join("debug")
            .join("aws_secretsmanager_agent"),
        PathBuf::from("..")
            .join("target")
            .join("release")
            .join("aws_secretsmanager_agent"),
        PathBuf::from("..")
            .join("target")
            .join("debug")
            .join("aws_secretsmanager_agent"),
    ];

    let agent_path = possible_paths
        .iter()
        .find(|path| path.exists())
        .expect("Agent binary not found");

    let mut child = TokioCommand::new(agent_path)
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start agent");

    // Read stdout until we see the "listening" message
    let stdout = child.stdout.take().expect("Failed to get stdout");
    let mut reader = BufReader::new(stdout).lines();

    let mut found_listening = false;
    loop {
        match reader.next_line().await {
            Ok(Some(line)) => {
                if line.contains("listening on") {
                    found_listening = true;
                    break;
                }
            }
            Ok(None) => {
                // Stream ended without finding listening message
                break;
            }
            Err(e) => {
                let _ = child.kill().await;
                panic!("Failed to read agent output: {}", e);
            }
        }
    }

    if !found_listening {
        let _ = child.kill().await;
        panic!("Agent failed to start - no listening message found");
    }

    AgentProcess { child, port }
}

pub async fn make_agent_request(port: u16, query: &AgentQuery) -> String {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .expect("Failed to build HTTP client");
    let mut url = Url::parse(&format!("http://localhost:{}/secretsmanager/get", port))
        .expect("Failed to parse URL");
    url.set_query(Some(&query.to_query_string()));

    let response = client
        .get(url)
        .header("X-Aws-Parameters-Secrets-Token", "test-token-123")
        .send()
        .await
        .expect("Failed to make agent request");

    assert_eq!(response.status(), 200);
    response.text().await.expect("Failed to read response body")
}

pub async fn setup_test_secrets() -> String {
    let test_prefix = format!(
        "aws-sm-agent-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );

    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    // Create basic test secret
    let secret_name = format!("{}-basic", test_prefix);
    client
        .create_secret()
        .name(&secret_name)
        .description("Basic test secret for aws-secretsmanager-agent")
        .secret_string(r#"{"username":"testuser","password":"testpass123"}"#)
        .send()
        .await
        .expect("Failed to create test secret");

    test_prefix
}

pub async fn cleanup_test_secrets(test_prefix: &str) {
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    let secret_name = format!("{}-basic", test_prefix);
    let _ = client
        .delete_secret()
        .secret_id(&secret_name)
        .force_delete_without_recovery(true)
        .send()
        .await;
}
