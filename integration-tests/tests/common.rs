use aws_config;
use aws_sdk_secretsmanager;
use std::env;
use std::fmt;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;

pub const AGENT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct AgentQuery {
    pub secret_id: String,
    pub version_id: Option<String>,
    pub version_stage: Option<String>,
    pub refresh_now: Option<bool>,
}

impl AgentQuery {
    pub fn new(secret_id: impl Into<String>) -> Self {
        Self {
            secret_id: secret_id.into(),
            version_id: None,
            version_stage: None,
            refresh_now: None,
        }
    }

    pub fn with_version_id(mut self, version_id: impl Into<String>) -> Self {
        self.version_id = Some(version_id.into());
        self
    }

    pub fn with_version_stage(mut self, version_stage: impl Into<String>) -> Self {
        self.version_stage = Some(version_stage.into());
        self
    }

    pub fn with_refresh_now(mut self, refresh_now: bool) -> Self {
        self.refresh_now = Some(refresh_now);
        self
    }
}

impl fmt::Display for AgentQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "secretId={}", self.secret_id)?;

        if let Some(version_id) = &self.version_id {
            write!(f, "&versionId={}", version_id)?;
        }

        if let Some(version_stage) = &self.version_stage {
            write!(f, "&versionStage={}", version_stage)?;
        }

        if let Some(refresh_now) = self.refresh_now {
            write!(f, "&refreshNow={}", refresh_now)?;
        }

        Ok(())
    }
}

pub struct AgentProcess {
    pub child: std::process::Child,
    pub port: u16,
}

impl Drop for AgentProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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
        "./target/release/aws_secretsmanager_agent",
        "./target/debug/aws_secretsmanager_agent",
        "../target/release/aws_secretsmanager_agent",
        "../target/debug/aws_secretsmanager_agent",
    ];

    let agent_path = possible_paths
        .iter()
        .find(|path| std::path::Path::new(path).exists())
        .expect("Agent binary not found");

    let mut child = Command::new(agent_path)
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start agent");

    // Wait for agent to start
    let start_time = std::time::Instant::now();
    loop {
        if start_time.elapsed() > AGENT_TIMEOUT {
            let _ = child.kill();
            panic!("Agent failed to start within timeout");
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .connect_timeout(Duration::from_millis(200))
            .build()
            .expect("Failed to build HTTP client");

        if let Ok(response) = client
            .get(&format!("http://localhost:{}/ping", port))
            .send()
            .await
        {
            if response.status() == 200 {
                break;
            }
        }

        sleep(Duration::from_millis(100)).await;
    }

    AgentProcess { child, port }
}

pub async fn make_agent_request(port: u16, query: &AgentQuery) -> String {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .expect("Failed to build HTTP client");
    let response = client
        .get(&format!(
            "http://localhost:{}/secretsmanager/get?{}",
            port, query
        ))
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
