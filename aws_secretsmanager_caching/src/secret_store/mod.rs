mod memory_store;

pub use memory_store::MemoryStore;
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt::Debug};

use crate::output::GetSecretValueOutputDef;

/// Response of the GetSecretValue API
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetSecretValueOutput(pub GetSecretValueOutputDef);

/// SecretStore trait
/// Any struct that implements this trait can be used as a secret store.
pub trait SecretStore: Debug + Send + Sync {
    /// Get the secret value from the store
    fn get_secret_value<'a>(
        &'a self,
        secret_id: &'a str,
        version_id: Option<&'a str>,
        version_stage: Option<&'a str>,
    ) -> Result<GetSecretValueOutputDef, SecretStoreError>;

    /// Write the secret value to the store
    fn write_secret_value(
        &mut self,
        secret_id: String,
        version_id: Option<String>,
        version_stage: Option<String>,
        data: GetSecretValueOutputDef,
    ) -> Result<(), SecretStoreError>;
}

/// All possible error types
#[derive(thiserror::Error, Debug)]
pub enum SecretStoreError {
    /// Secret not found
    #[error("Secrets Manager can't find the specified secret.")]
    ResourceNotFound,

    /// Secret cache TTL expired
    #[error("cache expired")]
    CacheExpired(Box<GetSecretValueOutputDef>),

    /// An unexpected error occurred
    #[error("unhandled error {0:?}")]
    Unhandled(#[source] Box<dyn Error + Send + Sync + 'static>),
}
