// #![warn(missing_docs)]
#![warn(
    missing_debug_implementations,
    missing_docs,
    rustdoc::missing_crate_level_docs
)]

//! AWS Secrets Manager Caching Library

/// Error types
mod error;
/// Output of secret store
pub mod output;
/// Manages the lifecycle of cached secrets
pub mod secret_store;

use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use error::is_transient_error;
use secret_store::SecretStoreError;

use output::GetSecretValueOutputDef;
use secret_store::{MemoryStore, SecretStore};
use std::{error::Error, num::NonZeroUsize, time::Duration};
use tokio::sync::RwLock;

/// AWS Secrets Manager Caching client
#[derive(Debug)]
pub struct SecretsManagerCachingClient {
    /// Secrets Manager client to retrieve secrets.
    asm_client: SecretsManagerClient,
    /// A store used to cache secrets.
    store: RwLock<Box<dyn SecretStore>>,
    static_stability: bool,
}

impl SecretsManagerCachingClient {
    /// Create a new caching client with in-memory store
    ///
    /// # Arguments
    ///
    /// * `asm_client` - Initialized AWS SDK Secrets Manager client instance
    /// * `max_size` - Maximum size of the store.
    /// * `ttl` - Time-to-live of the secrets in the store.
    /// * `static_stability` - Whether the client should serve cached data on transient refresh errors
    pub fn new(
        asm_client: SecretsManagerClient,
        max_size: NonZeroUsize,
        ttl: Duration,
        static_stability: bool,
    ) -> Result<Self, SecretStoreError> {
        Ok(Self {
            asm_client,
            store: RwLock::new(Box::new(MemoryStore::new(max_size, ttl))),
            static_stability,
        })
    }

    /// Retrieves the value of the secret from the specified version.
    ///
    /// # Arguments
    ///
    /// * `secret_id` - The ARN or name of the secret to retrieve.
    /// * `version_id` - The version id of the secret version to retrieve.
    /// * `version_stage` - The staging label of the version of the secret to retrieve.
    pub async fn get_secret_value(
        &self,
        secret_id: &str,
        version_id: Option<&str>,
        version_stage: Option<&str>,
    ) -> Result<GetSecretValueOutputDef, Box<dyn Error>> {
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
                match self
                    .refresh_secret_value(
                        secret_id,
                        version_id,
                        version_stage,
                        Some(cached_value.clone()),
                    )
                    .await
                {
                    Ok(r) => Ok(r),
                    Err(e) => Err(e.into()),
                }
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
        if let Some(cached_value) = cached_value {
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
                return Ok(*cached_value);
            }
        }

        let response = self
            .asm_client
            .get_secret_value()
            .secret_id(secret_id)
            .set_version_id(version_id.map(String::from))
            .set_version_stage(version_stage.map(String::from))
            .send()
            .await?;

        let result: GetSecretValueOutputDef = response.into();

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
            Err(e) if self.static_stability => {
                return match is_transient_error(&e) {
                    true => Ok(true),
                    false => Err(e.into()),
                }
            }
            Err(e) => return Err(e.into()),
        };

        let real_vids_to_stages = match describe.version_ids_to_stages() {
            Some(vids_to_stages) => vids_to_stages,
            // Secret has no version Ids
            None => return Ok(false),
        };

        let cached_version_id = &cached_value.version_id.clone().unwrap();

        if let Some(version_id) = version_id {
            // If we are requesting the same version id already in the cache, and that version ID still exists in AWS Secrets Manager
            // then the value is current
            let version_ids_match = version_id.eq(cached_version_id);

            // If a version stage was requested, check that it matches the one in the cache
            let version_stages_match = match version_stage {
                Some(version_stage) => match cached_value.version_stages {
                    Some(version_stages) => version_stages.contains(&version_stage.to_owned()),
                    // Version stage parameter was requested but was not found in the cache, forward request to AWS Secrets Manager
                    None => false,
                },
                // No version stage requested, we don't need to check that it's valid
                None => true,
            };

            return Ok(version_ids_match && version_stages_match);
        }

        // Version id parameter was not specified

        // If no version stage was passed, check AWSCURRENT
        let version_stage = match version_stage {
            Some(v) => v.to_owned(),
            None => "AWSCURRENT".to_owned(),
        };

        if let Some(cached_stages) = cached_value.version_stages {
            // IF The desired label matches the one in the cache
            if cached_stages.contains(&version_stage)
            // AND version ids to stages in AWS Secrets Manager contains the version label
            && real_vids_to_stages
            .iter()
            // AND the version id in AWS Secrets Manager already matches the version id in the cache
                    .any(|(k, v)| k.eq(cached_version_id) && v.contains(&version_stage))
            {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::sleep;

    use super::*;

    fn fake_client(ttl: Option<Duration>) -> SecretsManagerCachingClient {
        SecretsManagerCachingClient::new(
            asm_mock::def_fake_client(),
            NonZeroUsize::new(1000).unwrap(),
            match ttl {
                Some(ttl) => ttl,
                None => Duration::from_secs(1000),
            },
            false,
        )
        .expect("client should create")
    }

    #[tokio::test]
    async fn test_get_secret_value() {
        let client = fake_client(None);
        let secret_id = "test_secret";

        let response = client
            .get_secret_value(secret_id, None, None)
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
        let client = fake_client(None);
        let secret_id = "test_secret";
        let version_id = "test_version";

        let response = client
            .get_secret_value(secret_id, Some(version_id), None)
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
        let client = fake_client(None);
        let secret_id = "test_secret";
        let stage_label = "STAGEHERE";

        let response = client
            .get_secret_value(secret_id, None, Some(stage_label))
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
        let client = fake_client(None);
        let secret_id = "test_secret";
        let version_id = "test_version";
        let stage_label = "STAGEHERE";

        let response = client
            .get_secret_value(secret_id, Some(version_id), Some(stage_label))
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
        let client = fake_client(Some(Duration::from_secs(0)));
        let secret_id = "test_secret";

        // Run through this twice to test the cache expiration
        for i in 0..2 {
            let response = client
                .get_secret_value(secret_id, None, None)
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
        let client = fake_client(None);
        let secret_id = "KMSACCESSDENIEDabcdef";

        client
            .get_secret_value(secret_id, None, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn test_get_secret_value_resource_not_found() {
        let client = fake_client(None);
        let secret_id = "NOTFOUNDfasefasef";

        client
            .get_secret_value(secret_id, None, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_is_current_default_succeeds() {
        let client = fake_client(Some(Duration::from_secs(0)));
        let secret_id = "test_secret";

        let res1 = client
            .get_secret_value(secret_id, None, None)
            .await
            .unwrap();

        sleep(Duration::from_millis(10)).await;

        let res2 = client
            .get_secret_value(secret_id, None, None)
            .await
            .unwrap();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_is_current_version_id_succeeds() {
        let client = fake_client(Some(Duration::from_secs(0)));
        let secret_id = "test_secret";
        let version_id = Some("test_version");

        let res1 = client
            .get_secret_value(secret_id, version_id, None)
            .await
            .unwrap();

        sleep(Duration::from_millis(10)).await;

        let res2 = client
            .get_secret_value(secret_id, version_id, None)
            .await
            .unwrap();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_is_current_version_stage_succeeds() {
        let client = fake_client(Some(Duration::from_secs(0)));
        let secret_id = "test_secret";
        let version_stage = Some("VERSIONSTAGE");

        let res1 = client
            .get_secret_value(secret_id, None, version_stage)
            .await
            .unwrap();

        sleep(Duration::from_millis(10)).await;

        let res2 = client
            .get_secret_value(secret_id, None, version_stage)
            .await
            .unwrap();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_is_current_both_version_id_and_version_stage_succeeds() {
        let client = fake_client(Some(Duration::from_secs(0)));
        let secret_id = "test_secret";
        let version_id = Some("test_version");
        let version_stage = Some("VERSIONSTAGE");

        let res1 = client
            .get_secret_value(secret_id, version_id, version_stage)
            .await
            .unwrap();

        sleep(Duration::from_millis(10)).await;

        let res2 = client
            .get_secret_value(secret_id, version_id, version_stage)
            .await
            .unwrap();

        assert_eq!(res1, res2)
    }

    #[tokio::test]
    async fn test_is_current_describe_access_denied_fails() {
        let client = fake_client(Some(Duration::from_secs(0)));
        let secret_id = "DESCRIBEACCESSDENIED_test_secret";
        let version_id = Some("test_version");

        client
            .get_secret_value(secret_id, version_id, None)
            .await
            .unwrap();

        sleep(Duration::from_millis(10)).await;

        match client.get_secret_value(secret_id, version_id, None).await {
            Ok(_) => panic!("Expected failure"),
            Err(_) => (),
        }
    }

    mod asm_mock {
        use aws_sdk_secretsmanager as secretsmanager;
        use aws_smithy_runtime::client::http::test_util::infallible_client_fn;
        use aws_smithy_types::body::SdkBody;
        use http::{Request, Response};
        use secretsmanager::config::BehaviorVersion;
        use serde_json::Value;

        pub const FAKE_ARN: &str =
            "arn:aws:secretsmanager:us-west-2:123456789012:secret:{{name}}-NhBWsc";
        pub const DEFAULT_VERSION: &str = "5767290c-d089-49ed-b97c-17086f8c9d79";
        pub const DEFAULT_LABEL: &str = "AWSCURRENT";

        // Template GetSecretValue responses for testing
        const GSV_BODY: &str = r###"{
        "ARN": "{{arn}}",
        "Name": "{{name}}",
        "VersionId": "{{version}}",
        "SecretString": "hunter2",
        "VersionStages": [
            "{{label}}"
        ],
        "CreatedDate": 1569534789.046
        }"###;

        // Template DescribeSecret responses for testing
        const DESC_BODY: &str = r###"{
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

        // Private helper to look at the request and provide the correct reponse.
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
                "secretsmanager.DescribeSecret" => (200, DESC_BODY),
                _ => panic!("Unknown operation"),
            };

            // Fill in the template and return the response.
            let rsp = template
                .replace("{{arn}}", FAKE_ARN)
                .replace("{{name}}", name)
                .replace("{{version}}", version)
                .replace("{{label}}", label);
            (code, rsp)
        }

        // Test client that stubs off network call and provides a canned response.
        pub fn def_fake_client() -> secretsmanager::Client {
            let fake_creds = secretsmanager::config::Credentials::new(
                "AKIDTESTKEY",
                "astestsecretkey",
                Some("atestsessiontoken".to_string()),
                None,
                "",
            );
            let http_client = infallible_client_fn(|_req| {
                let (code, rsp) = format_rsp(_req);
                Response::builder()
                    .status(code)
                    .body(SdkBody::from(rsp))
                    .unwrap()
            });

            secretsmanager::Client::from_conf(
                secretsmanager::Config::builder()
                    .behavior_version(BehaviorVersion::latest())
                    .credentials_provider(fake_creds)
                    .region(secretsmanager::config::Region::new("us-west-2"))
                    .http_client(http_client)
                    .build(),
            )
        }
    }
}
