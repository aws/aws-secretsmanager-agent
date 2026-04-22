use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwapOption;
use aws_config::profile::ProfileFileCredentialsProvider;
use aws_credential_types::provider::{error::CredentialsError, future, ProvideCredentials};
use aws_credential_types::Credentials;
use aws_runtime::env_config::file::{EnvConfigFileKind, EnvConfigFiles};
use tokio::task::JoinHandle;

/// How often the background task checks for updated credentials on disk.
fn reload_delay() -> Duration {
    #[cfg(debug_assertions)]
    if let Ok(secs) = std::env::var("SMA_CREDENTIALS_RELOAD_SECS") {
        if let Ok(val) = secs.parse() {
            return Duration::from_secs(val);
        }
    }
    Duration::from_secs(5 * 60)
}

/// How long the SDK considers the credentials valid before asking the provider again.
/// Set below the minimum AssumeRole duration (15 min) to provide buffer for short-lived credentials.
const SDK_CREDENTIALS_TTL: Duration = Duration::from_secs(10 * 60);

/// A credentials provider that reads AWS credentials from a file and
/// automatically reloads them on a configurable interval.
///
/// The credentials file must be in the standard AWS credentials file format:
/// ```text
/// [default]
/// aws_access_key_id = AKIAIOSFODNN7EXAMPLE
/// aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
/// aws_session_token = FwoGZX...
/// ```
#[derive(Debug, Clone)]
pub struct FileBasedCredentialsProvider {
    cached: Arc<ArcSwapOption<Credentials>>,
    _reload_handle: Arc<ReloadHandle>,
}

/// Aborts the background reload task when dropped.
#[derive(Debug)]
struct ReloadHandle(JoinHandle<()>);

impl Drop for ReloadHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl FileBasedCredentialsProvider {
    /// Create a new provider that reads credentials from the given path.
    ///
    /// Attempts an initial load but does not fail if the file is missing,
    /// empty, or malformed — the agent can still serve cached secrets and
    /// the background reload task will pick up valid credentials when they
    /// appear.
    pub async fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let cached = Arc::new(ArcSwapOption::new(None));

        // Attempt initial load — log warnings on failure instead of failing.
        match load_from_file(&path).await {
            Ok(creds) => {
                cached.store(Some(Arc::new(creds)));
                warn_if_broad_permissions(&path);
                log::info!("Loaded file-based credentials from: {}", path.display());
            }
            Err(e) => {
                log::warn!(
                    "Could not load credentials from {}: {}. \
                     The agent will retry every {} seconds.",
                    path.display(),
                    e,
                    reload_delay().as_secs()
                );
            }
        }

        // Start background reload
        let reload_cached = cached.clone();
        let handle = tokio::spawn(async move {
            let mut last_modified = file_modified_time(&path);
            let mut interval = tokio::time::interval(reload_delay());
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;

                let current_modified = file_modified_time(&path);
                if current_modified == last_modified {
                    continue;
                }

                match load_from_file(&path).await {
                    Ok(creds) => {
                        reload_cached.store(Some(Arc::new(creds)));
                        last_modified = current_modified;
                        warn_if_broad_permissions(&path);
                        log::debug!("Successfully reloaded credentials from {}", path.display());
                    }
                    Err(e) => {
                        // Do not update last_modified here — if the file was
                        // partially written, we want to retry on the next cycle
                        // even if the mtime hasn't changed again.
                        log::warn!(
                            "Failed to reload credentials from {}: {}",
                            path.display(),
                            e
                        );
                    }
                }
            }
        });

        Self {
            cached,
            _reload_handle: Arc::new(ReloadHandle(handle)),
        }
    }
}

impl ProvideCredentials for FileBasedCredentialsProvider {
    fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        future::ProvideCredentials::new(async {
            self.cached
                .load()
                .as_ref()
                .map(|c| with_expiry((**c).clone()))
                .ok_or_else(|| CredentialsError::not_loaded("No credentials available"))
        })
    }
}

/// Parse credentials from a file using the AWS SDK's profile file parser.
async fn load_from_file(path: &Path) -> Result<Credentials, CredentialsError> {
    let env_config_files = EnvConfigFiles::builder()
        .with_file(EnvConfigFileKind::Credentials, path)
        .build();

    ProfileFileCredentialsProvider::builder()
        .profile_files(env_config_files)
        .build()
        .provide_credentials()
        .await
}

/// Wrap credentials with an SDK expiry so the SDK knows when to ask again.
fn with_expiry(creds: Credentials) -> Credentials {
    Credentials::new(
        creds.access_key_id(),
        creds.secret_access_key(),
        creds.session_token().map(|s| s.to_string()),
        Some(SystemTime::now() + SDK_CREDENTIALS_TTL),
        "FileBasedCredentialsProvider",
    )
}

fn file_modified_time(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Log a warning if the credentials file has permissions more permissive than owner-only (0600).
#[cfg(unix)]
fn warn_if_broad_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = std::fs::metadata(path) {
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            log::warn!(
                "Credentials file {} has broad permissions ({:o}). \
                 Consider restricting to owner-only (chmod 600).",
                path.display(),
                mode & 0o777
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_broad_permissions(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_fake_credentials(file: &mut NamedTempFile) {
        writeln!(
            file,
            "[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI\naws_session_token=FwoGZX"
        )
        .unwrap();
    }

    #[tokio::test]
    async fn test_load_valid_credentials() {
        let mut tmp = NamedTempFile::new().unwrap();
        write_fake_credentials(&mut tmp);

        let provider = FileBasedCredentialsProvider::new(tmp.path()).await;
        let creds = provider.provide_credentials().await.unwrap();

        assert_eq!(creds.access_key_id(), "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(creds.secret_access_key(), "wJalrXUtnFEMI");
        assert_eq!(creds.session_token(), Some("FwoGZX"));
    }

    #[tokio::test]
    async fn test_missing_file_starts_with_empty_cache() {
        let provider = FileBasedCredentialsProvider::new("/nonexistent/path").await;
        let result = provider.provide_credentials().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_empty_file_starts_with_empty_cache() {
        let tmp = NamedTempFile::new().unwrap();
        let provider = FileBasedCredentialsProvider::new(tmp.path()).await;
        let result = provider.provide_credentials().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_credential_reload() {
        let mut tmp = NamedTempFile::new().unwrap();
        write_fake_credentials(&mut tmp);

        let provider = FileBasedCredentialsProvider::new(tmp.path()).await;
        assert_eq!(
            provider
                .provide_credentials()
                .await
                .unwrap()
                .access_key_id(),
            "AKIAIOSFODNN7EXAMPLE"
        );

        // Real sleep to let the background task reach its interval.tick().await
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Simulate credential rotation
        std::fs::write(
            tmp.path(),
            "[default]\naws_access_key_id=ROTATED_KEY\naws_secret_access_key=secret\naws_session_token=token",
        )
        .unwrap();

        // Bump mtime so the reload detects a change
        tmp.as_file()
            .set_modified(SystemTime::now() + Duration::from_secs(60))
            .unwrap();

        // Advance past the reload delay, then resume and let the async
        // ProfileFileCredentialsProvider complete. Per tokio docs, advance()
        // "will not wait for the sleep calls it advanced past to complete"
        // so we resume real time and sleep to let all async work finish.
        tokio::time::pause();
        tokio::time::advance(reload_delay()).await;
        tokio::time::resume();
        tokio::time::sleep(Duration::from_secs(1)).await;

        assert_eq!(
            provider
                .provide_credentials()
                .await
                .unwrap()
                .access_key_id(),
            "ROTATED_KEY"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_permission_change_retains_cached_credentials() {
        use std::os::unix::fs::PermissionsExt;

        let mut tmp = NamedTempFile::new().unwrap();
        write_fake_credentials(&mut tmp);

        let provider = FileBasedCredentialsProvider::new(tmp.path()).await;
        assert_eq!(
            provider
                .provide_credentials()
                .await
                .unwrap()
                .access_key_id(),
            "AKIAIOSFODNN7EXAMPLE"
        );

        // Write to the file to bump mtime so the reload task detects a change
        std::fs::write(tmp.path(), "invalid").unwrap();
        // Now remove read permission so load_from_file fails
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o000)).unwrap();

        // Real sleep to let the background task reach its interval.tick().await
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Trigger reload cycle
        tokio::time::pause();
        tokio::time::advance(reload_delay()).await;
        tokio::time::resume();
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Cached credentials should still be available
        assert_eq!(
            provider
                .provide_credentials()
                .await
                .unwrap()
                .access_key_id(),
            "AKIAIOSFODNN7EXAMPLE"
        );

        // Restore permissions for cleanup
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[tokio::test]
    async fn test_failed_reload_then_valid_creds_same_mtime() {
        let mut tmp = NamedTempFile::new().unwrap();
        write_fake_credentials(&mut tmp);

        let provider = FileBasedCredentialsProvider::new(tmp.path()).await;
        assert_eq!(
            provider
                .provide_credentials()
                .await
                .unwrap()
                .access_key_id(),
            "AKIAIOSFODNN7EXAMPLE"
        );

        tokio::time::sleep(Duration::from_secs(1)).await;

        // Write invalid content with a known mtime
        let bad_mtime = SystemTime::now() + Duration::from_secs(120);
        std::fs::write(tmp.path(), "not valid credentials").unwrap();
        tmp.as_file().set_modified(bad_mtime).unwrap();

        tokio::time::pause();
        tokio::time::advance(reload_delay()).await;
        tokio::time::resume();
        tokio::time::sleep(Duration::from_secs(1)).await;

        assert_eq!(
            provider
                .provide_credentials()
                .await
                .unwrap()
                .access_key_id(),
            "AKIAIOSFODNN7EXAMPLE"
        );

        // Write valid credentials with the SAME mtime
        std::fs::write(
            tmp.path(),
            "[default]\naws_access_key_id=RECOVERED_KEY\naws_secret_access_key=secret\naws_session_token=token",
        )
        .unwrap();
        tmp.as_file().set_modified(bad_mtime).unwrap();

        tokio::time::pause();
        tokio::time::advance(reload_delay()).await;
        tokio::time::resume();
        tokio::time::sleep(Duration::from_secs(1)).await;

        assert_eq!(
            provider
                .provide_credentials()
                .await
                .unwrap()
                .access_key_id(),
            "RECOVERED_KEY",
        );
    }
}
