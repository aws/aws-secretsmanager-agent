use std::env;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

pub const AGENT_TIMEOUT: Duration = Duration::from_secs(30);

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
        
        if let Ok(response) = reqwest::get(&format!("http://localhost:{}/ping", port)).await {
            if response.status() == 200 {
                break;
            }
        }
        
        sleep(Duration::from_millis(100));
    }
    
    AgentProcess { child, port }
}

pub async fn make_agent_request(port: u16, query: &str) -> String {
    let client = reqwest::Client::new();
    let response = client
        .get(&format!("http://localhost:{}/secretsmanager/get?{}", port, query))
        .header("X-Aws-Parameters-Secrets-Token", "test-token-123")
        .send()
        .await
        .expect("Failed to make agent request");
    
    assert_eq!(response.status(), 200);
    response.text().await.expect("Failed to read response body")
}

pub fn get_test_secret_prefix() -> String {
    env::var("TEST_SECRET_PREFIX").expect("TEST_SECRET_PREFIX not set")
}