// #![warn(missing_docs)]
#![warn(
    missing_debug_implementations,
    missing_docs,
    rustdoc::missing_crate_level_docs
)]

//! AWS Secrets Manager Caching Library

/// Error types
pub mod error;
/// Output of secret store
pub mod output;
/// Manages the lifecycle of cached secrets
pub mod secret_store;
mod utils;

use aws_config::BehaviorVersion;
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use error::is_transient_error;
use secret_store::SecretStoreError;

use output::GetSecretValueOutputDef;
use secret_store::{MemoryStore, SecretStore};
use std::{error::Error, num::NonZeroUsize, time::Duration};
use tokio::sync::RwLock;
use utils::CachingLibraryInterceptor;

/// AWS Secrets Manager Caching client
#[derive(Debug)]
pub struct SecretsManagerCachingClient {
    /// Secrets Manager client to retrieve secrets.
    asm_client: SecretsManagerClient,
    /// A store used to cache secrets.
    store: RwLock<Box<dyn SecretStore>>,
    ignore_transient_errors: bool,
}

impl SecretsManagerCachingClient {
    /// Create a new caching client with in-memory store
    ///
    /// # Arguments
    ///
    /// * `asm_client` - Initialized AWS SDK Secrets Manager client instance
    /// * `max_size` - Maximum size of the store.
    /// * `ttl` - Time-to-live of the secrets in the store.
    /// * `ignore_transient_errors` - Whether the client should serve cached data on transient refresh errors
    /// ```rust
    /// use aws_sdk_secretsmanager::Client as SecretsManagerClient;
    /// use aws_sdk_secretsmanager::{config::Region, Config};
    /// use aws_secretsmanager_caching::SecretsManagerCachingClient;
    /// use std::num::NonZeroUsize;
    /// use std::time::Duration;

    /// let asm_client = SecretsManagerClient::from_conf(
    /// Config::builder()
    ///     .behavior_version_latest()
    ///     .build(),
    /// );
    /// let client = SecretsManagerCachingClient::new(
    ///     asm_client,
    ///     NonZeroUsize::new(1000).unwrap(),
    ///     Duration::from_secs(300),
    ///     false,
    /// );
    /// ```
    pub fn new(
        asm_client: SecretsManagerClient,
        max_size: NonZeroUsize,
        ttl: Duration,
        ignore_transient_errors: bool,
    ) -> Result<Self, SecretStoreError> {
        Ok(Self {
            asm_client,
            store: RwLock::new(Box::new(MemoryStore::new(max_size, ttl))),
            ignore_transient_errors,
        })
    }

    /// Create a new caching client with in-memory store and the default AWS SDK client configuration
    ///
    /// # Arguments
    ///
    /// * `max_size` - Maximum size of the store.
    /// * `ttl` - Time-to-live of the secrets in the store.
    /// ```rust
    /// tokio_test::block_on(async {
    /// use aws_secretsmanager_caching::SecretsManagerCachingClient;
    /// use std::num::NonZeroUsize;
    /// use std::time::Duration;
    ///
    /// let client = SecretsManagerCachingClient::default(
    /// NonZeroUsize::new(1000).unwrap(),
    /// Duration::from_secs(300),
    /// ).await.unwrap();
    /// })
    /// ```
    pub async fn default(max_size: NonZeroUsize, ttl: Duration) -> Result<Self, SecretStoreError> {
        let default_config = &aws_config::load_defaults(BehaviorVersion::latest()).await;
        let asm_builder = aws_sdk_secretsmanager::config::Builder::from(default_config)
            .interceptor(CachingLibraryInterceptor);

        let asm_client = SecretsManagerClient::from_conf(asm_builder.build());
        Self::new(asm_client, max_size, ttl, false)
    }

    /// Create a new caching client with in-memory store from an AWS SDK client builder
    ///
    /// # Arguments
    ///
    /// * `asm_builder` - AWS Secrets Manager SDK client builder.
    /// * `max_size` - Maximum size of the store.
    /// * `ttl` - Time-to-live of the secrets in the store.
    ///
    /// ```rust
    /// tokio_test::block_on(async {
    /// use aws_secretsmanager_caching::SecretsManagerCachingClient;
    /// use std::num::NonZeroUsize;
    /// use std::time::Duration;
    /// use aws_config::{BehaviorVersion, Region};

    /// let config = aws_config::load_defaults(BehaviorVersion::latest())
    /// .await
    /// .into_builder()
    /// .region(Region::from_static("us-west-2"))
    /// .build();

    /// let asm_builder = aws_sdk_secretsmanager::config::Builder::from(&config);

    /// let client = SecretsManagerCachingClient::from_builder(
    /// asm_builder,
    /// NonZeroUsize::new(1000).unwrap(),
    /// Duration::from_secs(300),
    /// false,
    /// )
    /// .await.unwrap();
    /// })
    /// ```
    pub async fn from_builder(
        asm_builder: aws_sdk_secretsmanager::config::Builder,
        max_size: NonZeroUsize,
        ttl: Duration,
        ignore_transient_errors: bool,
    ) -> Result<Self, SecretStoreError> {
        let asm_client = SecretsManagerClient::from_conf(
            asm_builder.interceptor(CachingLibraryInterceptor).build(),
        );
        Self::new(asm_client, max_size, ttl, ignore_transient_errors)
    }

    /// Retrieves the value of the secret from the specified version.
    ///
    /// # Arguments
    ///
    /// * `secret_id` - The ARN or name of the secret to retrieve.
    /// * `version_id` - The version id of the secret version to retrieve.
    /// * `version_stage` - The staging label of the version of the secret to retrieve.
    /// * `refresh_now` - Whether to serve from the cache or fetch from ASM.
    pub async fn get_secret_value(
        &self,
        secret_id: &str,
        version_id: Option<&str>,
        version_stage: Option<&str>,
        refresh_now: bool,
    ) -> Result<GetSecretValueOutputDef, Box<dyn Error>> {
        if refresh_now {
            return Ok(self
                .refresh_secret_value(secret_id, version_id, version_stage, None)
                .await?);
        }

        let read_lock = self.store.read().await;

        match read_lock.get_secret_value(secret_id, version_id, version_stage) {
            Ok(r) => Ok(r),
            Err(SecretStoreError::ResourceNotFound) => {
                drop(read_lock);
                Ok(self
                    .refresh_secret_value(secret_id, version_id, version_stage, None)
                    .await?)
            }
            Err(SecretStoreError::CacheExpired(cached_value)) => {
                drop(read_lock);
                Ok(self
                    .refresh_secret_value(secret_id, version_id, version_stage, Some(cached_value))
                    .await?)
            }
            Err(e) => Err(Box::new(e)),
        }
    }

    /// Refreshes the secret value through a GetSecretValue call to ASM
    ///
    /// # Arguments
    /// * `secret_id` - The ARN or name of the secret to retrieve.
    /// * `version_id` - The version id of the secret version to retrieve.
    /// * `version_stage` - The staging label of the version of the secret to retrieve.
    /// * `cached_value` - The value currently in the cache.
    async fn refresh_secret_value(
        &self,
        secret_id: &str,
        version_id: Option<&str>,
        version_stage: Option<&str>,
        cached_value: Option<Box<GetSecretValueOutputDef>>,
    ) -> Result<GetSecretValueOutputDef, Box<dyn Error>> {
        if let Some(ref cached_value) = cached_value {
            // The cache already had a value in it, we can quick-refresh it if the value is still current.
            if self
                .is_current(version_id, version_stage, cached_value.clone())
                .await?
            {
                // Re-up the entry freshness (TTL, cache rank) by writing the same data back to the cache.
                self.store.write().await.write_secret_value(
                    secret_id.to_owned(),
                    version_id.map(String::from),
                    version_stage.map(String::from),
                    *cached_value.clone(),
                )?;
                // Serve the cached value
                return Ok(*cached_value.clone());
            }
        }

        let result: GetSecretValueOutputDef = match self
            .asm_client
            .get_secret_value()
            .secret_id(secret_id)
            .set_version_id(version_id.map(String::from))
            .set_version_stage(version_stage.map(String::from))
            .send()
            .await
        {
            Ok(r) => r.into(),
            Err(e)
                if self.ignore_transient_errors
                    && is_transient_error(&e)
                    && cached_value.is_some() =>
            {
                *cached_value.unwrap()
            }
            Err(e) => Err(e)?,
        };

        self.store.write().await.write_secret_value(
            secret_id.to_owned(),
            version_id.map(String::from),
            version_stage.map(String::from),
            result.clone(),
        )?;

        Ok(result)
    }

    /// Check if the value in the cache is still fresh enough to be served again
    ///
    /// # Arguments
    /// * `version_id` - The version id of the secret version to retrieve.
    /// * `version_stage` - The staging label of the version of the secret to retrieve. Defaults to AWSCURRENT
    /// * `cached_value` - The value currently in the cache.
    ///
    /// # Returns
    /// * true if value can be reused, false if not
    async fn is_current(
        &self,
        version_id: Option<&str>,
        version_stage: Option<&str>,
        cached_value: Box<GetSecretValueOutputDef>,
    ) -> Result<bool, Box<dyn Error>> {
        let describe = match self
            .asm_client
            .describe_secret()
            .secret_id(cached_value.arn.unwrap())
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) if self.ignore_transient_errors && is_transient_error(&e) => return Ok(true),
            Err(e) => Err(e)?,
        };

        let real_vids_to_stages = match describe.version_ids_to_stages() {
            Some(vids_to_stages) => vids_to_stages,
            // Secret has no version Ids
            None => return Ok(false),
        };

        #[allow(clippy::unnecessary_unwrap)]
        // Only version id is given, then check if the version id still exists
        if version_id.is_some() && version_stage.is_none() {
            return Ok(real_vids_to_stages
                .iter()
                .any(|(k, _)| k.eq(version_id.unwrap())));
        }

        // If no version id is given, use the cached version id
        let version_id = match version_id {
            Some(id) => id.to_owned(),
            None => cached_value.version_id.clone().unwrap(),
        };

        // If no version stage was passed, check AWSCURRENT
        let version_stage = match version_stage {
            Some(v) => v.to_owned(),
            None => "AWSCURRENT".to_owned(),
        };

        // True if the version id and version stage match real_vids_to_stages in AWS Secrets Manager
        Ok(real_vids_to_stages
            .iter()
            .any(|(k, v)| k.eq(&version_id) && v.contains(&version_stage)))
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::sleep;

    use super::*;

    use aws_smithy_runtime_api::client::http::SharedHttpClient;

    fn fake_client(
        ttl: Option<Duration>,
        ignore_transient_errors: bool,
        http_client: Option<SharedHttpClient>,
        endpoint_url: Option<String>,
    ) -> SecretsManagerCachingClient {
        SecretsManagerCachingClient::new(
            asm_mock::def_fake_client(http_client, endpoint_url),
            NonZeroUsize::new(1000).unwrap(),
            match ttl {
                Some(ttl) => ttl,
                None => Duration::from_secs(1000),
            },
            ignore_transient_errors,
        )
        .expect("client should create")
    }

    #[tokio::test]
    async fn test_get_secret_value() {
        let client = fake_client(None, false, None, None);
        let secret_id = "test_secret";

        let response = client
            .get_secret_value(secret_id, None, None, false)
            .await
            .unwrap();

        assert_eq!(response.name, Some(secret_id.to_string()));
        assert_eq!(response.secret_string, Some("hunter2".to_string()));
        assert_eq!(
            response.arn,
            Some(
                asm_mock::FAKE_ARN
                    .replace("{{name}}", secret_id)
                    .to_string()
            )
        );
        assert_eq!(
            response.version_stages,
            Some(vec!["AWSCURRENT".to_string()])
        );
    }

    #[tokio::test]
    async fn test_get_secret_value_version_id() {
        let client = fake_client(None, false, None, None);
        let secret_id = "test_secret";
        let version_id = "test_version";

        let response = client
            .get_secret_value(secret_id, Some(version_id), None, false)
            .await
            .unwrap();

        assert_eq!(response.name, Some(secret_id.to_string()));
        assert_eq!(response.secret_string, Some("hunter2".to_string()));
        assert_eq!(response.version_id, Some(version_id.to_string()));
        assert_eq!(
            response.arn,
            Some(
                asm_mock::FAKE_ARN
                    .replace("{{name}}", secret_id)
                    .to_string()
            )
        );
        assert_eq!(
            response.version_stages,
            Some(vec!["AWSCURRENT".to_string()])
        );
    }

    #[tokio::test]
    async fn test_get_secret_value_version_stage() {
        let client = fake_client(None, false, None, None);
        let secret_id = "test_secret";
        let stage_label = "STAGEHERE";

        let response = client
            .get_secret_value(secret_id, None, Some(stage_label), false)
            .await
            .unwrap();

        assert_eq!(response.name, Some(secret_id.to_string()));
        assert_eq!(response.secret_string, Some("hunter2".to_string()));
        assert_eq!(
            response.arn,
            Some(
                asm_mock::FAKE_ARN
                    .replace("{{name}}", secret_id)
                    .to_string()
            )
        );
        assert_eq!(response.version_stages, Some(vec![stage_label.to_string()]));
    }

    #[tokio::test]
    async fn test_get_secret_value_version_id_and_stage() {
        let client = fake_client(None, false, None, None);
        let secret_id = "test_secret";
        let version_id = "test_version";
        let stage_label = "STAGEHERE";

        let response = client
            .get_secret_value(secret_id, Some(version_id), Some(stage_label), false)
            .await
            .unwrap();

        assert_eq!(response.name, Some(secret_id.to_string()));
        assert_eq!(response.secret_string, Some("hunter2".to_string()));
        assert_eq!(response.version_id, Some(version_id.to_string()));
        assert_eq!(
            response.arn,
            Some(
                asm_mock::FAKE_ARN
                    .replace("{{name}}", secret_id)
                    .to_string()
            )
        );
        assert_eq!(response.version_stages, Some(vec![stage_label.to_string()]));
    }

    #[tokio::test]
    async fn test_get_cache_expired() {
        let client = fake_client(Some(Duration::from_secs(0)), false, None, None);
        let secret_id = "test_secret";

        // Run through this twice to test the cache expiration
        for i in 0..2 {
            let response = client
                .get_secret_value(secret_id, None, None, false)
                .await
                .unwrap();

            assert_eq!(response.name, Some(secret_id.to_string()));
            assert_eq!(response.secret_string, Some("hunter2".to_string()));
            assert_eq!(
                response.arn,
                Some(
                    asm_mock::FAKE_ARN
                        .replace("{{name}}", secret_id)
                        .to_string()
                )
            );
            assert_eq!(
                response.version_stages,
                Some(vec!["AWSCURRENT".to_string()])
            );
            // let the entry expire
            if i == 0 {
                sleep(Duration::from_millis(50)).await;
            }
        }
    }

    #[tokio::test]
    #[should_panic]
    async fn test_get_secret_value_kms_access_denied() {
        let client = fake_client(None, false, None, None);
        let secret_id = "KMSACCESSDENIEDabcdef";

        client
            .get_secret_value(secret_id, None, None, false)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn test_get_secret_value_resource_not_found() {
        let client = fake_client(None, false, None, None);
        let secret_id = "NOTFOUNDfasefasef";

        client
            .get_secret_value(secret_id, None, None, false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_is_current_default_succeeds() {
        let client = fake_client(Some(Duration::from_secs(0)), false, None, None);
        let secret_id = "test_secret";

        let res1 = client
            .get_secret_value(secret_id, None, None, false)
            .await
            .unwrap();

        let res2 = client
            .get_secret_value(secret_id, None, None, false)
            .await
            .unwrap();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_is_current_version_id_succeeds() {
        let client = fake_client(Some(Duration::from_secs(0)), false, None, None);
        let secret_id = "test_secret";
        let version_id = Some("test_version");

        let res1 = client
            .get_secret_value(secret_id, version_id, None, false)
            .await
            .unwrap();

        let res2 = client
            .get_secret_value(secret_id, version_id, None, false)
            .await
            .unwrap();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_is_current_version_stage_succeeds() {
        let client = fake_client(Some(Duration::from_secs(0)), false, None, None);
        let secret_id = "test_secret";
        let version_stage = Some("VERSIONSTAGE");

        let res1 = client
            .get_secret_value(secret_id, None, version_stage, false)
            .await
            .unwrap();

        let res2 = client
            .get_secret_value(secret_id, None, version_stage, false)
            .await
            .unwrap();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_is_current_both_version_id_and_version_stage_succeeds() {
        let client = fake_client(Some(Duration::from_secs(0)), false, None, None);
        let secret_id = "test_secret";
        let version_id = Some("test_version");
        let version_stage = Some("VERSIONSTAGE");

        let res1 = client
            .get_secret_value(secret_id, version_id, version_stage, false)
            .await
            .unwrap();

        let res2 = client
            .get_secret_value(secret_id, version_id, version_stage, false)
            .await
            .unwrap();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_is_current_describe_access_denied_fails() {
        let client = fake_client(Some(Duration::from_secs(0)), false, None, None);
        let secret_id = "DESCRIBEACCESSDENIED_test_secret";
        let version_id = Some("test_version");

        client
            .get_secret_value(secret_id, version_id, None, false)
            .await
            .unwrap();

        if (client
            .get_secret_value(secret_id, version_id, None, false)
            .await)
            .is_ok()
        {
            panic!("Expected failure")
        }
    }

    #[tokio::test]
    async fn test_is_current_describe_timeout_error_succeeds() {
        use asm_mock::GSV_BODY;
        use aws_smithy_runtime::client::http::test_util::wire::{ReplayedEvent, WireMockServer};

        let mock = WireMockServer::start(vec![
            ReplayedEvent::with_body(GSV_BODY),
            ReplayedEvent::Timeout,
        ])
        .await;
        let client = fake_client(
            Some(Duration::from_secs(0)),
            true,
            Some(mock.http_client()),
            Some(mock.endpoint_url()),
        );
        let secret_id = "DESCRIBETIMEOUT_test_secret";
        let version_id = Some("test_version");

        let res1 = client
            .get_secret_value(secret_id, version_id, None, false)
            .await
            .unwrap();

        let res2 = client
            .get_secret_value(secret_id, version_id, None, false)
            .await
            .unwrap();

        mock.shutdown();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_is_current_describe_service_error_succeeds() {
        let client = fake_client(Some(Duration::from_secs(0)), true, None, None);
        let secret_id = "DESCRIBESERVICEERROR_test_secret";
        let version_id = Some("test_version");
        let version_stage = Some("VERSIONSTAGE");

        let res1 = client
            .get_secret_value(secret_id, version_id, version_stage, false)
            .await
            .unwrap();

        let res2 = client
            .get_secret_value(secret_id, version_id, version_stage, false)
            .await
            .unwrap();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_is_current_gsv_timeout_error_succeeds() {
        use asm_mock::DESC_BODY;
        use asm_mock::GSV_BODY;
        use aws_smithy_runtime::client::http::test_util::wire::{ReplayedEvent, WireMockServer};

        let mock = WireMockServer::start(vec![
            ReplayedEvent::with_body(
                GSV_BODY
                    .replace("{{version}}", "old_version")
                    .replace("{{label}}", "AWSCURRENT"),
            ),
            ReplayedEvent::with_body(
                DESC_BODY
                    .replace("{{version}}", "new_version")
                    .replace("{{label}}", "AWSCURRENT"),
            ),
            ReplayedEvent::Timeout,
        ])
        .await;
        let client = fake_client(
            Some(Duration::from_secs(0)),
            true,
            Some(mock.http_client()),
            Some(mock.endpoint_url()),
        );
        let secret_id = "GSVTIMEOUT_test_secret";

        let res1 = client
            .get_secret_value(secret_id, None, None, false)
            .await
            .unwrap();

        let res2 = client
            .get_secret_value(secret_id, None, None, false)
            .await
            .unwrap();

        mock.shutdown();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_get_secret_value_refresh_now_true() {
        let client = fake_client(Some(Duration::from_secs(30)), false, None, None);
        let secret_id = "REFRESHNOW_test_secret";

        let response1 = client
            .get_secret_value(secret_id, None, None, false)
            .await
            .unwrap();

        assert_eq!(response1.name, Some(secret_id.to_string()));
        assert_eq!(
            response1.arn,
            Some(
                asm_mock::FAKE_ARN
                    .replace("{{name}}", secret_id)
                    .to_string()
            )
        );
        assert_eq!(
            response1.version_stages,
            Some(vec!["AWSCURRENT".to_string()])
        );

        sleep(Duration::from_millis(1)).await;

        let response2 = client
            .get_secret_value(secret_id, None, None, true)
            .await
            .unwrap();

        assert_ne!(response1.secret_string, response2.secret_string);
        assert_eq!(response1.arn, response2.arn);
        assert_eq!(response1.version_stages, response2.version_stages);
    }

    #[tokio::test]
    async fn test_get_secret_value_refresh_now_false() {
        let client = fake_client(Some(Duration::from_secs(30)), false, None, None);
        let secret_id = "REFRESHNOW_test_secret";

        let response1 = client
            .get_secret_value(secret_id, None, None, false)
            .await
            .unwrap();

        assert_eq!(response1.name, Some(secret_id.to_string()));
        assert_eq!(
            response1.arn,
            Some(
                asm_mock::FAKE_ARN
                    .replace("{{name}}", secret_id)
                    .to_string()
            )
        );
        assert_eq!(
            response1.version_stages,
            Some(vec!["AWSCURRENT".to_string()])
        );

        sleep(Duration::from_millis(1)).await;

        let response2 = client
            .get_secret_value(secret_id, None, None, false)
            .await
            .unwrap();

        assert_eq!(response1, response2);
    }

    #[tokio::test]
    async fn test_get_secret_value_version_id_and_stage_refresh_now() {
        let client = fake_client(Some(Duration::from_secs(30)), false, None, None);
        let secret_id = "REFRESHNOW_test_secret";
        let version_id = "test_version";
        let stage_label = "STAGEHERE";

        let response1 = client
            .get_secret_value(secret_id, Some(version_id), Some(stage_label), false)
            .await
            .unwrap();

        sleep(Duration::from_millis(1)).await;

        let response2 = client
            .get_secret_value(secret_id, Some(version_id), Some(stage_label), true)
            .await
            .unwrap();

        assert_ne!(response1.secret_string, response2.secret_string);
        assert_eq!(response1.arn, response2.arn);
        assert_eq!(response1.version_stages, response2.version_stages);
    }

    mod asm_mock {
        use aws_sdk_secretsmanager as secretsmanager;
        use aws_smithy_runtime::client::http::test_util::infallible_client_fn;
        use aws_smithy_runtime_api::client::http::SharedHttpClient;
        use aws_smithy_types::body::SdkBody;
        use aws_smithy_types::timeout::TimeoutConfig;
        use http::{Request, Response};
        use secretsmanager::config::BehaviorVersion;
        use serde_json::Value;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        pub const FAKE_ARN: &str =
            "arn:aws:secretsmanager:us-west-2:123456789012:secret:{{name}}-NhBWsc";
        pub const DEFAULT_VERSION: &str = "5767290c-d089-49ed-b97c-17086f8c9d79";
        pub const DEFAULT_LABEL: &str = "AWSCURRENT";
        pub const DEFAULT_SECRET_STRING: &str = "hunter2";

        // Template GetSecretValue responses for testing
        pub const GSV_BODY: &str = r###"{
        "ARN": "{{arn}}",
        "Name": "{{name}}",
        "VersionId": "{{version}}",
        "SecretString": "{{secret}}",
        "VersionStages": [
            "{{label}}"
        ],
        "CreatedDate": 1569534789.046
        }"###;

        // Template DescribeSecret responses for testing
        pub const DESC_BODY: &str = r###"{
          "ARN": "{{arn}}",
          "Name": "{{name}}",
          "Description": "My test secret",
          "KmsKeyId": "arn:aws:kms:us-west-2:123456789012:key/exampled-90ab-cdef-fedc-bbd6-7e6f303ac933",
          "LastChangedDate": 1523477145.729,
          "LastAccessedDate": 1524572133.25,
          "VersionIdsToStages": {
              "{{version}}": [
                  "{{label}}"
              ]
          },
          "CreatedDate": 1569534789.046
        }"###;

        // Template for access denied testing
        const KMS_ACCESS_DENIED_BODY: &str = r###"{
        "__type":"AccessDeniedException",
        "Message":"Access to KMS is not allowed"
        }"###;

        // Template for testing resource not found with DescribeSecret
        const NOT_FOUND_EXCEPTION_BODY: &str = r###"{
        "__type":"ResourceNotFoundException",
        "message":"Secrets Manager can't find the specified secret."
        }"###;

        const SECRETSMANAGER_ACCESS_DENIED_BODY: &str = r###"{
        "__type:"AccessDeniedException",
        "Message": "is not authorized to perform: secretsmanager:DescribeSecret on resource: XXXXXXXX"
        }"###;

        const SECRETSMANAGER_INTERNAL_SERVICE_ERROR_BODY: &str = r###"{
        "__type:"InternalServiceError",
        "Message": "Internal service error"
        }"###;

        // Private helper to look at the request and provide the correct response.
        fn format_rsp(req: Request<SdkBody>) -> (u16, String) {
            let (parts, body) = req.into_parts();

            let req_map: serde_json::Map<String, Value> =
                serde_json::from_slice(body.bytes().unwrap()).unwrap();
            let version = req_map
                .get("VersionId")
                .map_or(DEFAULT_VERSION, |x| x.as_str().unwrap());
            let label = req_map
                .get("VersionStage")
                .map_or(DEFAULT_LABEL, |x| x.as_str().unwrap());
            let name = req_map.get("SecretId").unwrap().as_str().unwrap(); // Does not handle full ARN case.

            let secret_string = match name {
                secret if secret.starts_with("REFRESHNOW") => SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
                    .to_string(),
                _ => DEFAULT_SECRET_STRING.to_string(),
            };

            let (code, template) = match parts.headers["x-amz-target"].to_str().unwrap() {
                "secretsmanager.GetSecretValue" if name.starts_with("KMSACCESSDENIED") => {
                    (400, KMS_ACCESS_DENIED_BODY)
                }
                "secretsmanager.GetSecretValue" if name.starts_with("NOTFOUND") => {
                    (400, NOT_FOUND_EXCEPTION_BODY)
                }
                "secretsmanager.GetSecretValue" => (200, GSV_BODY),
                "secretsmanager.DescribeSecret" if name.contains("DESCRIBEACCESSDENIED") => {
                    (400, SECRETSMANAGER_ACCESS_DENIED_BODY)
                }
                "secretsmanager.DescribeSecret" if name.contains("DESCRIBESERVICEERROR") => {
                    (500, SECRETSMANAGER_INTERNAL_SERVICE_ERROR_BODY)
                }
                "secretsmanager.DescribeSecret" => (200, DESC_BODY),
                _ => panic!("Unknown operation"),
            };

            // Fill in the template and return the response.
            let rsp = template
                .replace("{{arn}}", FAKE_ARN)
                .replace("{{name}}", name)
                .replace("{{version}}", version)
                .replace("{{secret}}", &secret_string)
                .replace("{{label}}", label);
            (code, rsp)
        }

        // Test client that stubs off network call and provides a canned response.
        pub fn def_fake_client(
            http_client: Option<SharedHttpClient>,
            endpoint_url: Option<String>,
        ) -> secretsmanager::Client {
            let fake_creds = secretsmanager::config::Credentials::new(
                "AKIDTESTKEY",
                "astestsecretkey",
                Some("atestsessiontoken".to_string()),
                None,
                "",
            );

            let mut config_builder = secretsmanager::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .credentials_provider(fake_creds)
                .region(secretsmanager::config::Region::new("us-west-2"))
                .timeout_config(
                    TimeoutConfig::builder()
                        .operation_attempt_timeout(Duration::from_millis(100))
                        .build(),
                )
                .http_client(match http_client {
                    Some(custom_client) => custom_client,
                    None => infallible_client_fn(|_req| {
                        let (code, rsp) = format_rsp(_req);
                        Response::builder()
                            .status(code)
                            .body(SdkBody::from(rsp))
                            .unwrap()
                    }),
                });
            config_builder = match endpoint_url {
                Some(endpoint_url) => config_builder.endpoint_url(endpoint_url),
                None => config_builder,
            };

            secretsmanager::Client::from_conf(config_builder.build())
        }
    }
}
