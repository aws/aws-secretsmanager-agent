use aws_config;
use aws_sdk_secretsmanager;
use derive_builder::Builder;
use std::env;
use std::fmt;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as TokioCommand;
use url::Url;

#[derive(Debug, Clone, Copy)]
pub enum SecretType {
    Basic,
    Binary,
    Versioned,
    Large,
}

impl fmt::Display for SecretType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretType::Basic => write!(f, "basic"),
            SecretType::Binary => write!(f, "binary"),
            SecretType::Versioned => write!(f, "versioned"),
            SecretType::Large => write!(f, "large"),
        }
    }
}

const ALL_SECRET_TYPES: [SecretType; 4] = [
    SecretType::Basic,
    SecretType::Binary,
    SecretType::Versioned,
    SecretType::Large,
];

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

impl AgentProcess {
    pub async fn start() -> AgentProcess {
        Self::start_with_config(2775, 5).await
    }

    pub async fn start_with_config(port: u16, ttl_seconds: u16) -> AgentProcess {
        let config_content = format!(
            r#"
http_port = {}
log_level = "info"
ttl_seconds = {}
cache_size = 100
validate_credentials = true
"#,
            port, ttl_seconds
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
            .kill_on_drop(true)
            .spawn()
            .expect("Failed to start agent");

        // Read stdout until we see the "listening" message
        let stdout = child.stdout.take().expect("Failed to get stdout");
        let mut reader = BufReader::new(stdout).lines();

        match reader.next_line().await {
            Ok(Some(line)) => {
                if !line.contains("listening on") {
                    panic!("Agent failed to start - no listening message found");
                }
            }
            Ok(None) => {
                panic!("Stream ended without finding listening message");
            }
            Err(e) => {
                panic!("Failed to read agent output: {}", e);
            }
        }

        AgentProcess { child, port }
    }

    pub async fn make_request(&self, query: &AgentQuery) -> String {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to build HTTP client");
        let mut url = Url::parse(&format!(
            "http://localhost:{}/secretsmanager/get",
            self.port
        ))
        .expect("Failed to parse URL");
        url.set_query(Some(&query.to_query_string()));

        let response = client
            .get(url)
            .header("X-Aws-Parameters-Secrets-Token", "test-token-123")
            .send()
            .await
            .expect("Failed to make agent request");

        let status = response.status();
        if status != 200 {
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error body".to_string());
            panic!("Agent returned status {}: {}", status, error_body);
        }
        response.text().await.expect("Failed to read response body")
    }
}

pub struct TestSecrets {
    pub prefix: String,
}

impl TestSecrets {
    pub fn secret_name(&self, secret_type: SecretType) -> String {
        format!("{}-{}", self.prefix, secret_type)
    }

    pub async fn setup() -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let test_prefix = format!("aws-sm-agent-test-{}", timestamp);

        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = aws_sdk_secretsmanager::Client::new(&config);

        let temp_secrets = Self {
            prefix: test_prefix.clone(),
        };

        // Create basic test secret
        let secret_name = temp_secrets.secret_name(SecretType::Basic);
        client
            .create_secret()
            .name(&secret_name)
            .description("Basic test secret for aws-secretsmanager-agent")
            .secret_string(r#"{"username":"testuser","password":"testpass123"}"#)
            .send()
            .await
            .expect("Failed to create test secret");

        // Create binary test secret
        let binary_secret_name = temp_secrets.secret_name(SecretType::Binary);
        let binary_data = b"\x00\x01\x02\x03\xFF\xFE\xFD";
        client
            .create_secret()
            .name(&binary_secret_name)
            .description("Binary test secret for aws-secretsmanager-agent")
            .secret_binary(aws_sdk_secretsmanager::primitives::Blob::new(binary_data))
            .send()
            .await
            .expect("Failed to create binary test secret");

        // Create versioned test secret
        let versioned_secret_name = temp_secrets.secret_name(SecretType::Versioned);
        client
            .create_secret()
            .name(&versioned_secret_name)
            .description("Versioned test secret for aws-secretsmanager-agent")
            .secret_string(r#"{"username":"currentuser","password":"currentpass"}"#)
            .send()
            .await
            .expect("Failed to create versioned test secret");

        // Create AWSPENDING version using put_secret_value
        client
            .put_secret_value()
            .secret_id(&versioned_secret_name)
            .secret_string(r#"{"username":"pendinguser","password":"pendingpass"}"#)
            .version_stages("AWSPENDING")
            .send()
            .await
            .expect("Failed to create AWSPENDING version");

        // Create large test secret (near 64KB limit)
        let large_secret_name = temp_secrets.secret_name(SecretType::Large);
        let large_data = "x".repeat(60000); // ~60KB of data
        let large_secret_json = format!(r#"{{"data":"{}","size":"60KB"}}"#, large_data);
        client
            .create_secret()
            .name(&large_secret_name)
            .description("Large test secret for aws-secretsmanager-agent")
            .secret_string(&large_secret_json)
            .send()
            .await
            .expect("Failed to create large test secret");

        temp_secrets
    }

    pub async fn wait_for_pending_version(
        &self,
        secret_type: SecretType,
    ) -> Result<(), tokio::time::error::Elapsed> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let (_, pending_version) = self.get_version_ids(secret_type).await;
                if !pending_version.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
    }

    pub async fn get_version_ids(&self, secret_type: SecretType) -> (String, String) {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = aws_sdk_secretsmanager::Client::new(&config);
        let secret_name = self.secret_name(secret_type);

        let describe_response = client
            .describe_secret()
            .secret_id(&secret_name)
            .send()
            .await
            .expect("Failed to describe secret");

        let version_ids_to_stages = describe_response.version_ids_to_stages().unwrap();
        let mut current_version = String::new();
        let mut pending_version = String::new();

        for (version_id, stages) in version_ids_to_stages {
            if stages.contains(&"AWSCURRENT".to_string()) {
                current_version = version_id.clone();
            }
            if stages.contains(&"AWSPENDING".to_string()) {
                pending_version = version_id.clone();
            }
        }

        (current_version, pending_version)
    }
}

impl Drop for TestSecrets {
    fn drop(&mut self) {
        let prefix = self.prefix.clone();
        tokio::spawn(async move {
            let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            let client = aws_sdk_secretsmanager::Client::new(&config);

            for secret_type in ALL_SECRET_TYPES {
                let secret_name = format!("{}-{}", prefix, secret_type);
                let _ = client
                    .delete_secret()
                    .secret_id(&secret_name)
                    .force_delete_without_recovery(true)
                    .send()
                    .await;
            }
        });
    }
}
