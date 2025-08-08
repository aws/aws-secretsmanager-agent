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

#[cfg(debug_assertions)]
use log::info;

use output::GetSecretValueOutputDef;
use secret_store::{MemoryStore, SecretStore};

#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicU32, Ordering};

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
    #[cfg(debug_assertions)]
    metrics: CacheMetrics,
}

#[derive(Debug)]
#[cfg(debug_assertions)]
struct CacheMetrics {
    hits: AtomicU32,
    misses: AtomicU32,
    refreshes: AtomicU32,
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
            #[cfg(debug_assertions)]
            metrics: CacheMetrics {
                hits: AtomicU32::new(0),
                misses: AtomicU32::new(0),
                refreshes: AtomicU32::new(0),
            },
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
            #[cfg(debug_assertions)]
            {
                self.increment_counter(&self.metrics.refreshes);

                let (hit_rate, miss_rate) = self.get_cache_rates();

                info!(
                    "METRICS: Bypassing cache. Refreshing secret '{}' immediately. \
                    Total hits: {}. Total misses: {}. Total refreshes: {}. Hit rate: {:.2}%. Miss rate: {:.2}%",
                    secret_id,
                    self.get_counter_value(&self.metrics.hits),
                    self.get_counter_value(&self.metrics.misses),
                    self.get_counter_value(&self.metrics.refreshes),
                    hit_rate,
                    miss_rate
                );
            }

            return Ok(self
                .refresh_secret_value(secret_id, version_id, version_stage, None)
                .await?);
        }

        let read_lock = self.store.read().await;

        match read_lock.get_secret_value(secret_id, version_id, version_stage) {
            Ok(r) => {
                #[cfg(debug_assertions)]
                {
                    self.increment_counter(&self.metrics.hits);

                    let (hit_rate, miss_rate) = self.get_cache_rates();

                    info!(
                        "METRICS: Cache HIT for secret '{}'. Total hits: {}. Total misses: {}. \
                        Hit rate: {:.2}%. Miss rate: {:.2}%.",
                        secret_id,
                        self.get_counter_value(&self.metrics.hits),
                        self.get_counter_value(&self.metrics.misses),
                        hit_rate,
                        miss_rate
                    );
                }

                Ok(r)
            }
            Err(SecretStoreError::ResourceNotFound) => {
                #[cfg(debug_assertions)]
                {
                    self.increment_counter(&self.metrics.misses);

                    let (hit_rate, miss_rate) = self.get_cache_rates();

                    info!(
                        "METRICS: Cache MISS for secret '{}'. Total hits: {}. Total misses: {}. \
                        Hit rate: {:.2}%. Miss rate: {:.2}%.",
                        secret_id,
                        self.get_counter_value(&self.metrics.hits),
                        self.get_counter_value(&self.metrics.misses),
                        hit_rate,
                        miss_rate
                    );
                }

                drop(read_lock);
                Ok(self
                    .refresh_secret_value(secret_id, version_id, version_stage, None)
                    .await?)
            }
            Err(SecretStoreError::CacheExpired(cached_value)) => {
                #[cfg(debug_assertions)]
                {
                    self.increment_counter(&self.metrics.misses);

                    let (hit_rate, miss_rate) = self.get_cache_rates();

                    info!(
                        "METRICS: Cache entry expired for secret '{}'. Total hits: {}. Total \
                        misses: {}. Total refreshes: {}. Hit rate: {:.2}%. Miss rate: {:.2}%.",
                        secret_id,
                        self.get_counter_value(&self.metrics.hits),
                        self.get_counter_value(&self.metrics.misses),
                        self.get_counter_value(&self.metrics.refreshes),
                        hit_rate,
                        miss_rate
                    );
                }

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

    #[cfg(debug_assertions)]
    fn get_cache_rates(&self) -> (f64, f64) {
        let hits = self.metrics.hits.load(Ordering::Relaxed);
        let misses = self.metrics.misses.load(Ordering::Relaxed);
        let total = hits + misses;

        if total == 0 {
            return (0.0, 0.0);
        }

        let hit_rate = (hits as f64 / total as f64) * 100.0;

        (hit_rate, 100.0 - hit_rate)
    }

    #[cfg(debug_assertions)]
    fn increment_counter(&self, counter: &AtomicU32) -> () {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(debug_assertions)]
    fn get_counter_value(&self, counter: &AtomicU32) -> u32 {
        counter.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use aws_sdk_secretsmanager::{
        config::http::HttpResponse,
        operation::{
            describe_secret::{DescribeSecretError, DescribeSecretOutput},
            get_secret_value::{GetSecretValueError, GetSecretValueOutput},
        },
        types::error::ResourceNotFoundException,
    };
    use aws_smithy_mocks::{mock, mock_client, RuleMode};
    use aws_smithy_types::{body::SdkBody, error::ErrorMetadata};
    use tokio::time::sleep;

    use super::*;

    use aws_smithy_runtime_api::{client::result::SdkError, http::StatusCode};

    #[tokio::test]
    async fn test_get_secret_value() {
        let secret_id = "test_secret";
        let arn = "arn";

        let gsv = mock!(aws_sdk_secretsmanager::Client::get_secret_value)
            .match_requests(|req| req.secret_id() == Some(secret_id))
            .then_output(move || {
                GetSecretValueOutput::builder()
                    .name(secret_id)
                    .arn(arn)
                    .secret_string("hunter2")
                    .version_stages("AWSCURRENT")
                    .build()
            });

        let asm_mock = mock_client!(aws_sdk_secretsmanager, [&gsv]);

        let client = SecretsManagerCachingClient::new(
            asm_mock,
            NonZeroUsize::new(1000).unwrap(),
            Duration::from_secs(1000),
            true,
        )
        .unwrap();

        let response = client
            .get_secret_value(secret_id, None, None, false)
            .await
            .unwrap();

        assert_eq!(response.name, Some(secret_id.to_string()));
        assert_eq!(response.secret_string, Some("hunter2".to_string()));
        assert_eq!(response.arn, Some(arn.into()));
        assert_eq!(
            response.version_stages,
            Some(vec!["AWSCURRENT".to_string()])
        );
        assert_eq!(gsv.num_calls(), 1)
    }

    #[tokio::test]
    async fn test_get_secret_value_version_id() {
        let secret_id = "test_secret";
        let version_id = "test_version";
        let arn = "arn";

        let gsv = mock!(aws_sdk_secretsmanager::Client::get_secret_value)
            .match_requests(|req| {
                req.secret_id() == Some(secret_id) && req.version_id() == Some(version_id)
            })
            .then_output(move || {
                GetSecretValueOutput::builder()
                    .name(secret_id)
                    .arn(arn)
                    .secret_string("hunter2")
                    .version_id(version_id)
                    .version_stages("AWSCURRENT")
                    .build()
            });

        let asm_mock = mock_client!(aws_sdk_secretsmanager, [&gsv]);

        let client = SecretsManagerCachingClient::new(
            asm_mock,
            NonZeroUsize::new(1000).unwrap(),
            Duration::from_secs(1000),
            true,
        )
        .unwrap();

        let response = client
            .get_secret_value(secret_id, Some(version_id), None, false)
            .await
            .unwrap();

        assert_eq!(response.name, Some(secret_id.to_string()));
        assert_eq!(response.secret_string, Some("hunter2".to_string()));
        assert_eq!(response.version_id, Some(version_id.to_string()));
        assert_eq!(response.arn, Some(arn.into()));
        assert_eq!(
            response.version_stages,
            Some(vec!["AWSCURRENT".to_string()])
        );
        assert_eq!(gsv.num_calls(), 1)
    }

    #[tokio::test]
    async fn test_get_secret_value_version_stage() {
        let secret_id = "test_secret";
        let stage_label = "STAGEHERE";
        let arn = "arn";

        let gsv = mock!(aws_sdk_secretsmanager::Client::get_secret_value)
            .match_requests(|req| {
                req.secret_id() == Some(secret_id) && req.version_stage() == Some(stage_label)
            })
            .then_output(move || {
                GetSecretValueOutput::builder()
                    .name(secret_id)
                    .arn(arn)
                    .secret_string("hunter2")
                    .version_stages(stage_label)
                    .build()
            });

        let asm_mock = mock_client!(aws_sdk_secretsmanager, [&gsv]);

        let client = SecretsManagerCachingClient::new(
            asm_mock,
            NonZeroUsize::new(1000).unwrap(),
            Duration::from_secs(1000),
            true,
        )
        .unwrap();

        let response = client
            .get_secret_value(secret_id, None, Some(stage_label), false)
            .await
            .unwrap();

        assert_eq!(response.name, Some(secret_id.to_string()));
        assert_eq!(response.secret_string, Some("hunter2".to_string()));
        assert_eq!(response.arn, Some(arn.into()));
        assert_eq!(response.version_stages, Some(vec![stage_label.to_string()]));
        assert_eq!(gsv.num_calls(), 1)
    }

    #[tokio::test]
    async fn test_get_secret_value_version_id_and_stage() {
        let secret_id = "test_secret";
        let version_id = "test_version";
        let stage_label = "STAGEHERE";
        let arn = "arn";

        let gsv = mock!(aws_sdk_secretsmanager::Client::get_secret_value)
            .match_requests(|req| {
                req.secret_id() == Some(secret_id)
                    && req.version_stage() == Some(stage_label)
                    && req.version_id() == Some(version_id)
            })
            .then_output(move || {
                GetSecretValueOutput::builder()
                    .name(secret_id)
                    .arn(arn)
                    .secret_string("hunter2")
                    .version_stages(stage_label)
                    .version_id(version_id)
                    .build()
            });

        let asm_mock = mock_client!(aws_sdk_secretsmanager, [&gsv]);

        let client = SecretsManagerCachingClient::new(
            asm_mock,
            NonZeroUsize::new(1000).unwrap(),
            Duration::from_secs(1000),
            true,
        )
        .unwrap();

        let response = client
            .get_secret_value(secret_id, Some(version_id), Some(stage_label), false)
            .await
            .unwrap();

        assert_eq!(response.name, Some(secret_id.to_string()));
        assert_eq!(response.secret_string, Some("hunter2".to_string()));
        assert_eq!(response.version_id, Some(version_id.to_string()));
        assert_eq!(response.arn, Some(arn.into()));
        assert_eq!(response.version_stages, Some(vec![stage_label.to_string()]));
        assert_eq!(gsv.num_calls(), 1)
    }

    #[tokio::test]
    async fn test_get_cache_expired() {
        let secret_id = "test_secret";
        let version_id = "version_id";
        let version_stage = "AWSCURRENT";
        let arn = "arn";

        let gsv = mock!(aws_sdk_secretsmanager::Client::get_secret_value)
            .match_requests(|req| req.secret_id() == Some(secret_id))
            .then_output(move || {
                GetSecretValueOutput::builder()
                    .name(secret_id)
                    .arn(arn)
                    .secret_string("hunter2")
                    .version_id(version_id)
                    .version_stages(version_stage)
                    .build()
            });

        let describe_secret =
            mock!(aws_sdk_secretsmanager::Client::describe_secret).then_output(move || {
                // Don't serve the same value
                DescribeSecretOutput::builder()
                    .name(secret_id)
                    .version_ids_to_stages("different_version_id", vec![version_stage.into()])
                    .build()
            });

        let asm_mock = mock_client!(
            aws_sdk_secretsmanager,
            RuleMode::MatchAny,
            [&gsv, &describe_secret]
        );

        let client = SecretsManagerCachingClient::new(
            asm_mock,
            NonZeroUsize::new(1000).unwrap(),
            Duration::from_secs(0),
            true,
        )
        .unwrap();

        // Run through this twice to test the cache expiration
        for i in 0..2 {
            let response = client
                .get_secret_value(secret_id, None, None, false)
                .await
                .unwrap();

            assert_eq!(response.name, Some(secret_id.to_string()));
            assert_eq!(response.secret_string, Some("hunter2".to_string()));
            assert_eq!(response.arn, Some(arn.into()));
            assert_eq!(
                response.version_stages,
                Some(vec!["AWSCURRENT".to_string()])
            );
            // let the entry expire
            if i == 0 {
                sleep(Duration::from_millis(50)).await;
            }
        }

        assert_eq!(gsv.num_calls(), 2)
    }

    #[tokio::test]
    async fn test_get_secret_value_kms_access_denied() {
        let gsv =
            mock!(aws_sdk_secretsmanager::Client::get_secret_value).then_http_response(|| {
                HttpResponse::new(
                    StatusCode::try_from(400).unwrap(),
                    SdkBody::from(
                        r##"{
                            "__type":"AccessDeniedException",
                            "message":"Access to KMS is not allowed"
                        }"##,
                    ),
                )
            });

        let asm_mock = mock_client!(aws_sdk_secretsmanager, &[gsv]);

        let client = SecretsManagerCachingClient::new(
            asm_mock,
            NonZeroUsize::new(1000).unwrap(),
            Duration::from_secs(1000),
            true,
        )
        .unwrap();
        let secret_id = "KMSACCESSDENIEDabcdef";

        match client.get_secret_value(secret_id, None, None, false).await {
            Ok(_) => panic!(),
            Err(e) => e.to_string().contains("Access to KMS is not allowed"),
        };
    }

    #[tokio::test]
    async fn test_get_secret_value_resource_not_found() {
        let gsv = mock!(aws_sdk_secretsmanager::Client::get_secret_value).then_error(|| {
            GetSecretValueError::ResourceNotFoundException(
                ResourceNotFoundException::builder()
                    .message("Secrets Manager can't find the specified secret.")
                    .build(),
            )
        });

        let asm_mock = mock_client!(aws_sdk_secretsmanager, &[gsv]);

        let client = SecretsManagerCachingClient::new(
            asm_mock,
            NonZeroUsize::new(1000).unwrap(),
            Duration::from_secs(1000),
            true,
        )
        .unwrap();

        let secret_id = "NOTFOUNDfasefasef";

        match client.get_secret_value(secret_id, None, None, false).await {
            Ok(_) => panic!(),
            Err(e) => assert!(e
                .downcast::<SdkError<GetSecretValueError, HttpResponse>>()
                .unwrap()
                .into_service_error()
                .is_resource_not_found_exception()),
        };
    }

    #[tokio::test]
    async fn test_get_cache_is_current_fast_refreshes() {
        let secret_id = "test_secret";
        let version_id = "version_id";
        let version_stage = "AWSCURRENT";
        let arn = "arn";

        let gsv = mock!(aws_sdk_secretsmanager::Client::get_secret_value)
            .match_requests(|req| req.secret_id() == Some(secret_id))
            .then_output(move || {
                GetSecretValueOutput::builder()
                    .name(secret_id)
                    .arn(arn)
                    .secret_string("hunter2")
                    .version_id(version_id)
                    .version_stages(version_stage)
                    .build()
            });

        let describe_secret =
            mock!(aws_sdk_secretsmanager::Client::describe_secret).then_output(move || {
                // Cache is current. We fast-refresh
                DescribeSecretOutput::builder()
                    .name(secret_id)
                    .version_ids_to_stages(version_id, vec![version_stage.into()])
                    .build()
            });

        let asm_mock = mock_client!(
            aws_sdk_secretsmanager,
            RuleMode::MatchAny,
            [&gsv, &describe_secret]
        );

        let client = SecretsManagerCachingClient::new(
            asm_mock,
            NonZeroUsize::new(1000).unwrap(),
            Duration::from_secs(0),
            true,
        )
        .unwrap();

        // Run through this twice to test the cache expiration
        for i in 0..2 {
            let response = client
                .get_secret_value(secret_id, None, None, false)
                .await
                .unwrap();

            assert_eq!(response.name, Some(secret_id.to_string()));
            assert_eq!(response.secret_string, Some("hunter2".to_string()));
            assert_eq!(response.arn, Some(arn.into()));
            assert_eq!(
                response.version_stages,
                Some(vec!["AWSCURRENT".to_string()])
            );
            // let the entry expire
            if i == 0 {
                sleep(Duration::from_millis(50)).await;
            }
        }

        assert_eq!(gsv.num_calls(), 1);
        assert_eq!(describe_secret.num_calls(), 1);
    }

    #[tokio::test]
    async fn test_is_current_version_id_succeeds() {
        let secret_id = "test_secret";
        let version_id = "version_id";
        let version_stage = "AWSCURRENT";
        let arn = "arn";

        let gsv = mock!(aws_sdk_secretsmanager::Client::get_secret_value)
            .match_requests(|req| {
                req.secret_id() == Some(secret_id) && req.version_id() == Some(version_id)
            })
            .then_output(move || {
                GetSecretValueOutput::builder()
                    .name(secret_id)
                    .arn(arn)
                    .secret_string("hunter2")
                    .version_id(version_id)
                    .version_stages(version_stage)
                    .build()
            });

        let describe_secret =
            mock!(aws_sdk_secretsmanager::Client::describe_secret).then_output(move || {
                // Cache is current. We fast-refresh
                DescribeSecretOutput::builder()
                    .name(secret_id)
                    .version_ids_to_stages(version_id, vec![version_stage.into()])
                    .build()
            });

        let asm_mock = mock_client!(
            aws_sdk_secretsmanager,
            RuleMode::MatchAny,
            [&gsv, &describe_secret]
        );

        let client = SecretsManagerCachingClient::new(
            asm_mock,
            NonZeroUsize::new(1000).unwrap(),
            Duration::from_secs(0),
            true,
        )
        .unwrap();

        // Run through this twice to test the cache expiration
        for i in 0..2 {
            let response = client
                .get_secret_value(secret_id, Some(version_id), None, false)
                .await
                .unwrap();

            assert_eq!(response.name, Some(secret_id.to_string()));
            assert_eq!(response.secret_string, Some("hunter2".to_string()));
            assert_eq!(response.arn, Some(arn.into()));
            assert_eq!(
                response.version_stages,
                Some(vec!["AWSCURRENT".to_string()])
            );
            // let the entry expire
            if i == 0 {
                sleep(Duration::from_millis(50)).await;
            }
        }

        assert_eq!(gsv.num_calls(), 1);
        assert_eq!(describe_secret.num_calls(), 1);
    }

    #[tokio::test]
    async fn test_is_current_version_stage_succeeds() {
        let secret_id = "test_secret";
        let version_id = "version_id";
        let version_stage = "VERSIONSTAGE";
        let arn = "arn";

        let gsv = mock!(aws_sdk_secretsmanager::Client::get_secret_value)
            .match_requests(|req| {
                req.secret_id() == Some(secret_id) && req.version_stage() == Some(version_stage)
            })
            .then_output(move || {
                GetSecretValueOutput::builder()
                    .name(secret_id)
                    .arn(arn)
                    .secret_string("hunter2")
                    .version_id(version_id)
                    .version_stages(version_stage)
                    .build()
            });

        let describe_secret =
            mock!(aws_sdk_secretsmanager::Client::describe_secret).then_output(move || {
                // Cache is current. We fast-refresh
                DescribeSecretOutput::builder()
                    .name(secret_id)
                    .version_ids_to_stages(version_id, vec![version_stage.into()])
                    .build()
            });

        let asm_mock = mock_client!(
            aws_sdk_secretsmanager,
            RuleMode::MatchAny,
            [&gsv, &describe_secret]
        );

        let client = SecretsManagerCachingClient::new(
            asm_mock,
            NonZeroUsize::new(1000).unwrap(),
            Duration::from_secs(0),
            true,
        )
        .unwrap();

        // Run through this twice to test the cache expiration
        for i in 0..2 {
            let response = client
                .get_secret_value(secret_id, None, Some(version_stage), false)
                .await
                .unwrap();

            assert_eq!(response.name, Some(secret_id.to_string()));
            assert_eq!(response.secret_string, Some("hunter2".to_string()));
            assert_eq!(response.arn, Some(arn.into()));
            assert_eq!(
                response.version_stages,
                Some(vec![version_stage.to_string()])
            );
            // let the entry expire
            if i == 0 {
                sleep(Duration::from_millis(50)).await;
            }
        }

        assert_eq!(gsv.num_calls(), 1);
        assert_eq!(describe_secret.num_calls(), 1);
    }

    #[tokio::test]
    async fn test_is_current_both_version_id_and_version_stage_succeed() {
        let secret_id = "test_secret";
        let version_id = "version_id";
        let version_stage = "VERSIONSTAGE";
        let arn = "arn";

        let gsv = mock!(aws_sdk_secretsmanager::Client::get_secret_value)
            .match_requests(|req| {
                req.secret_id() == Some(secret_id)
                    && req.version_stage() == Some(version_stage)
                    && req.version_id() == Some(version_id)
            })
            .then_output(move || {
                GetSecretValueOutput::builder()
                    .name(secret_id)
                    .arn(arn)
                    .secret_string("hunter2")
                    .version_id(version_id)
                    .version_stages(version_stage)
                    .build()
            });

        let describe_secret =
            mock!(aws_sdk_secretsmanager::Client::describe_secret).then_output(move || {
                // Cache is current. We fast-refresh
                DescribeSecretOutput::builder()
                    .name(secret_id)
                    .version_ids_to_stages(version_id, vec![version_stage.into()])
                    .build()
            });

        let asm_mock = mock_client!(
            aws_sdk_secretsmanager,
            RuleMode::MatchAny,
            [&gsv, &describe_secret]
        );

        let client = SecretsManagerCachingClient::new(
            asm_mock,
            NonZeroUsize::new(1000).unwrap(),
            Duration::from_secs(0),
            true,
        )
        .unwrap();

        // Run through this twice to test the cache expiration
        for i in 0..2 {
            let response = client
                .get_secret_value(secret_id, Some(version_id), Some(version_stage), false)
                .await
                .unwrap();

            assert_eq!(response.name, Some(secret_id.to_string()));
            assert_eq!(response.secret_string, Some("hunter2".to_string()));
            assert_eq!(response.arn, Some(arn.into()));
            assert_eq!(
                response.version_stages,
                Some(vec![version_stage.to_string()])
            );
            // let the entry expire
            if i == 0 {
                sleep(Duration::from_millis(50)).await;
            }
        }

        assert_eq!(gsv.num_calls(), 1);
        assert_eq!(describe_secret.num_calls(), 1);
    }

    #[tokio::test]
    async fn test_is_current_describe_access_denied_fails() {
        let secret_id = "test_secret";
        let version_id = "version_id";
        let version_stage = "VERSIONSTAGE";
        let arn = "arn";
        let secret_string = "hunter2";

        let gsv = mock!(aws_sdk_secretsmanager::Client::get_secret_value)
            .match_requests(|req| {
                req.secret_id() == Some(secret_id)
                    && req.version_stage() == Some(version_stage)
                    && req.version_id() == Some(version_id)
            })
            .then_output(move || {
                GetSecretValueOutput::builder()
                    .name(secret_id)
                    .arn(arn)
                    .secret_string(secret_string)
                    .version_id(version_id)
                    .version_stages(version_stage)
                    .build()
            });

        let describe_secret =
            mock!(aws_sdk_secretsmanager::Client::describe_secret).then_error(|| {
                // TODO: Figure out how to set __type
                DescribeSecretError::generic(
                    ErrorMetadata::builder()
                        .code("400")
                        .message("is not authorized to perform: secretsmanager:DescribeSecret on resource: XXXXXXXX")
                        .build(),
                )
            });

        let asm_mock = mock_client!(
            aws_sdk_secretsmanager,
            RuleMode::MatchAny,
            [&gsv, &describe_secret]
        );

        let client = SecretsManagerCachingClient::new(
            asm_mock,
            NonZeroUsize::new(1000).unwrap(),
            Duration::from_secs(0),
            true,
        )
        .unwrap();

        // Run through this twice to test the cache expiration
        let response = client
            .get_secret_value(secret_id, Some(version_id), Some(version_stage), false)
            .await
            .unwrap();

        assert_eq!(response.name, Some(secret_id.to_string()));
        assert_eq!(response.secret_string, Some(secret_string.to_string()));
        assert_eq!(response.arn, Some(arn.into()));
        assert_eq!(
            response.version_stages,
            Some(vec![version_stage.to_string()])
        );
        // let the entry expire
        sleep(Duration::from_millis(50)).await;

        if client
            .get_secret_value(secret_id, Some(version_id), Some(version_stage), false)
            .await
            .is_ok()
        {
            panic!("Expected failure")
        }

        assert_eq!(gsv.num_calls(), 1)
    }

    #[tokio::test]
    async fn test_is_current_describe_service_error_succeeds() {
        let secret_id = "DESCRIBESERVICEERROR_test_secret";
        let version_id = "test_version";
        let version_stage = "VERSIONSTAGE";
        let arn = "arn";

        let gsv = mock!(aws_sdk_secretsmanager::Client::get_secret_value)
            .match_requests(|req| {
                req.secret_id() == Some(secret_id)
                    && req.version_stage() == Some(version_stage)
                    && req.version_id() == Some(version_id)
            })
            .then_output(move || {
                GetSecretValueOutput::builder()
                    .name(secret_id)
                    .arn(arn)
                    .secret_string("hunter2")
                    .version_id(version_id)
                    .version_stages(version_stage)
                    .build()
            });

        let describe_secret = mock!(aws_sdk_secretsmanager::Client::describe_secret)
            .then_http_response(|| {
                HttpResponse::new(
                    StatusCode::try_from(500).unwrap(),
                    SdkBody::from(
                        r##"{
                "__type": "InternalServiceError",
                "message": "Internal service error"
            }"##,
                    ),
                )
            });

        let asm_mock = mock_client!(
            aws_sdk_secretsmanager,
            RuleMode::MatchAny,
            [&gsv, &describe_secret]
        );
        let client = SecretsManagerCachingClient::new(
            asm_mock,
            NonZeroUsize::new(1000).unwrap(),
            Duration::ZERO,
            true,
        )
        .unwrap();

        let res1 = client
            .get_secret_value(secret_id, Some(version_id), Some(version_stage), false)
            .await
            .unwrap();

        let res2 = client
            .get_secret_value(secret_id, Some(version_id), Some(version_stage), false)
            .await
            .unwrap();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_get_secret_value_refresh_now_true() {
        let secret_id = "REFRESHNOW_test_secret";
        let arn = "arn";

        let gsv = mock!(aws_sdk_secretsmanager::Client::get_secret_value)
            .match_requests(|req| req.secret_id() == Some(secret_id))
            .sequence()
            .output(move || {
                GetSecretValueOutput::builder()
                    .name(secret_id)
                    .arn(arn)
                    .secret_string("hunter2")
                    .version_stages("AWSCURRENT")
                    .build()
            })
            .output(move || {
                GetSecretValueOutput::builder()
                    .name(secret_id)
                    .arn(arn)
                    .secret_string("some other string")
                    .version_stages("AWSCURRENT")
                    .build()
            })
            .build();

        let asm_mock = mock_client!(aws_sdk_secretsmanager, [&gsv]);
        let client = SecretsManagerCachingClient::new(
            asm_mock,
            NonZeroUsize::new(1000).unwrap(),
            Duration::from_secs(30),
            true,
        )
        .unwrap();

        let response1 = client
            .get_secret_value(secret_id, None, None, false)
            .await
            .unwrap();

        assert_eq!(response1.name, Some(secret_id.to_string()));
        assert_eq!(response1.arn, Some(arn.into()));
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

        assert_eq!(gsv.num_calls(), 2)
    }

    #[tokio::test]
    async fn test_get_secret_value_refresh_now_false() {
        let secret_id = "REFRESHNOW_test_secret";
        let arn = "arn";

        let gsv = mock!(aws_sdk_secretsmanager::Client::get_secret_value)
            .match_requests(|req| req.secret_id() == Some(secret_id))
            .sequence()
            .output(move || {
                GetSecretValueOutput::builder()
                    .name(secret_id)
                    .arn(arn)
                    .secret_string("hunter2")
                    .version_stages("AWSCURRENT")
                    .build()
            })
            .output(move || {
                GetSecretValueOutput::builder()
                    .name(secret_id)
                    .arn(arn)
                    .secret_string("some other string")
                    .version_stages("AWSCURRENT")
                    .build()
            })
            .build();

        let asm_mock = mock_client!(aws_sdk_secretsmanager, [&gsv]);
        let client = SecretsManagerCachingClient::new(
            asm_mock,
            NonZeroUsize::new(1000).unwrap(),
            Duration::from_secs(30),
            true,
        )
        .unwrap();

        let response1 = client
            .get_secret_value(secret_id, None, None, false)
            .await
            .unwrap();

        assert_eq!(response1.name, Some(secret_id.to_string()));
        assert_eq!(response1.arn, Some(arn.into()));
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

        assert_eq!(gsv.num_calls(), 1)
    }

    #[tokio::test]
    async fn test_get_secret_value_version_id_and_stage_refresh_now() {
        let secret_id = "REFRESHNOW_test_secret";
        let version_id = "test_version";
        let stage_label = "STAGEHERE";
        let arn = "arn";

        let gsv = mock!(aws_sdk_secretsmanager::Client::get_secret_value)
            .match_requests(|req| req.secret_id() == Some(secret_id))
            .sequence()
            .output(move || {
                GetSecretValueOutput::builder()
                    .name(secret_id)
                    .arn(arn)
                    .secret_string("hunter2")
                    .version_stages("AWSCURRENT")
                    .build()
            })
            .output(move || {
                GetSecretValueOutput::builder()
                    .name(secret_id)
                    .arn(arn)
                    .secret_string("some other string")
                    .version_stages("AWSCURRENT")
                    .build()
            })
            .build();

        let asm_mock = mock_client!(aws_sdk_secretsmanager, [&gsv]);
        let client = SecretsManagerCachingClient::new(
            asm_mock,
            NonZeroUsize::new(1000).unwrap(),
            Duration::from_secs(30),
            true,
        )
        .unwrap();

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

        assert_eq!(gsv.num_calls(), 2);
    }

    mod wire_tests {
        use aws_sdk_secretsmanager as secretsmanager;

        use aws_smithy_runtime::client::http::test_util::wire::WireMockServer;
        use aws_smithy_runtime_api::client::http::SharedHttpClient;

        use aws_smithy_types::timeout::TimeoutConfig;

        use secretsmanager::config::BehaviorVersion;

        use std::{num::NonZeroUsize, time::Duration};

        use crate::SecretsManagerCachingClient;

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

        // Test client that stubs off network call and provides a canned response.
        pub fn def_fake_client(
            http_client: SharedHttpClient,
            endpoint_url: String,
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
                .http_client(http_client);
            config_builder = config_builder.endpoint_url(endpoint_url);

            secretsmanager::Client::from_conf(config_builder.build())
        }

        fn fake_client(
            ttl: Option<Duration>,
            ignore_transient_errors: bool,
            wire_server: &WireMockServer,
        ) -> SecretsManagerCachingClient {
            SecretsManagerCachingClient::new(
                def_fake_client(wire_server.http_client(), wire_server.endpoint_url()),
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
        async fn test_is_current_gsv_timeout_error_succeeds() {
            use aws_smithy_runtime::client::http::test_util::wire::{
                ReplayedEvent, WireMockServer,
            };

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

            let client = fake_client(Some(Duration::from_secs(0)), true, &mock);

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
        async fn test_is_current_describe_timeout_error_succeeds() {
            // TODO: Figure out how to do this with mocks
            use aws_smithy_runtime::client::http::test_util::wire::{
                ReplayedEvent, WireMockServer,
            };

            let mock = WireMockServer::start(vec![
                ReplayedEvent::with_body(GSV_BODY),
                ReplayedEvent::Timeout,
            ])
            .await;
            let client = fake_client(Some(Duration::from_secs(0)), true, &mock);
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
    }
}
