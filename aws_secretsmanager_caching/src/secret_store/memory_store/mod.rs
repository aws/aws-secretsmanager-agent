mod cache;

use crate::output::GetSecretValueOutputDef;

use self::cache::Cache;

use super::{SecretStore, SecretStoreError};

use std::{
    num::NonZeroUsize,
    time::{Duration, Instant},
};

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct Key {
    secret_id: String,
    version_id: Option<String>,
    version_stage: Option<String>,
}

#[derive(Debug, Clone)]
struct GSVValue {
    value: GetSecretValueOutputDef,
    last_updated_at: Instant,
}

impl GSVValue {
    fn new(value: GetSecretValueOutputDef) -> Self {
        Self {
            value,
            last_updated_at: Instant::now(),
        }
    }
}

#[derive(Debug, Clone)]
/// In-memory secret store using an time and space bound cache
pub struct MemoryStore {
    gsv_cache: Cache<Key, GSVValue>,
    ttl: Duration,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new(NonZeroUsize::new(1000).unwrap(), Duration::from_secs(60))
    }
}

impl MemoryStore {
    /// Create a new memory store with the given max size and TTL
    pub fn new(max_size: NonZeroUsize, ttl: Duration) -> Self {
        Self {
            gsv_cache: Cache::new(max_size),
            ttl,
        }
    }
}

impl SecretStore for MemoryStore {
    fn get_secret_value(
        &self,
        secret_id: &str,
        version_id: Option<&str>,
        version_stage: Option<&str>,
    ) -> Result<GetSecretValueOutputDef, SecretStoreError> {
        match self.gsv_cache.get(&Key {
            secret_id: secret_id.to_string(),
            version_id: version_id.map(String::from),
            version_stage: version_stage.map(String::from),
        }) {
            Some(gsv) if gsv.last_updated_at.elapsed() > self.ttl => {
                Err(SecretStoreError::CacheExpired(Box::new(gsv.value.clone())))
            }
            Some(gsv) => Ok(gsv.clone().value),
            None => Err(SecretStoreError::ResourceNotFound),
        }
    }

    fn write_secret_value(
        &mut self,
        secret_id: String,
        version_id: Option<String>,
        version_stage: Option<String>,
        data: GetSecretValueOutputDef,
    ) -> Result<(), SecretStoreError> {
        self.gsv_cache.insert(
            Key {
                secret_id: secret_id.to_string(),
                version_id,
                version_stage,
            },
            GSVValue::new(data),
        );

        Ok(())
    }
}

/// Write the secret value to the store
#[cfg(test)]
mod tests {

    use core::panic;
    use std::thread;

    use crate::output::GetSecretValueOutputDef;

    use super::*;

    const NAME: &str = "test_name";
    const ARN: &str = "test_arn";
    const VERSION_ID: &str = "test_version_id";
    const SECRET_STRING: &str = "test_secret_string";

    fn get_secret_value_output(suffix: Option<&str>) -> GetSecretValueOutputDef {
        GetSecretValueOutputDef {
            name: match suffix {
                Some(suffix) => Some(format!("{}{}", NAME, suffix)),
                None => Some(NAME.to_string()),
            },
            arn: match suffix {
                Some(suffix) => Some(format!("{}{}", ARN, suffix)),
                None => Some(ARN.to_string()),
            },
            version_id: Some(VERSION_ID.to_string()),
            secret_string: Some(SECRET_STRING.to_string()),
            secret_binary: None,
            version_stages: Some(vec!["AWSCURRENT".to_string()]),
            created_date: None,
        }
    }

    fn store_secret(
        store: &mut MemoryStore,
        suffix: Option<&str>,
        version_id: Option<String>,
        stage: Option<String>,
    ) {
        let name = match suffix {
            Some(suffix) => format!("{}{}", NAME, suffix),
            None => NAME.to_string(),
        };

        store
            .write_secret_value(name, version_id, stage, get_secret_value_output(None))
            .unwrap();
    }

    #[test]
    fn memory_store_write_then_read_awscurrent() {
        let mut store = MemoryStore::default();

        store_secret(&mut store, None, None, None);

        match store.get_secret_value(NAME, None, None) {
            Ok(gsv) => {
                assert_eq!(gsv.name.unwrap(), NAME);
                assert_eq!(gsv.arn.unwrap(), ARN);
                assert_eq!(gsv.version_id.unwrap(), VERSION_ID);
                assert_eq!(gsv.secret_string.unwrap(), SECRET_STRING);
                assert_eq!(gsv.version_stages.unwrap().len(), 1);
                assert_eq!(gsv.created_date, None);
            }
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }

    #[test]
    fn memory_store_write_then_read_specific_stage() {
        let mut store = MemoryStore::default();

        store_secret(&mut store, None, None, Some("AWSCURRENT".to_string()));

        match store.get_secret_value(NAME, None, Some("AWSCURRENT")) {
            Ok(gsv) => {
                assert_eq!(gsv.name.unwrap(), NAME);
                assert_eq!(gsv.arn.unwrap(), ARN);
                assert_eq!(gsv.version_id.unwrap(), VERSION_ID);
                assert_eq!(gsv.secret_string.unwrap(), SECRET_STRING);
                assert_eq!(gsv.version_stages.unwrap().len(), 1);
                assert_eq!(gsv.created_date, None);
            }
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }

    #[test]
    fn memory_store_write_then_read_specific_version_id() {
        let mut store = MemoryStore::default();

        store_secret(&mut store, None, Some(VERSION_ID.to_string()), None);

        let gsv = store
            .get_secret_value(NAME, Some(VERSION_ID), None)
            .unwrap();

        assert_eq!(gsv.name.unwrap(), NAME);
        assert_eq!(gsv.arn.unwrap(), ARN);
        assert_eq!(gsv.version_id, Some(VERSION_ID.to_string()));
        assert_eq!(gsv.secret_string, Some(SECRET_STRING.to_string()));
        assert_eq!(gsv.version_stages, Some(vec!["AWSCURRENT".to_string()]));
        assert_eq!(gsv.created_date, None);
    }

    #[test]
    fn memory_store_read_cache_expired() {
        // Set TTL to 1ms to invalidate results right after GSV retrieval to store secret value
        let mut store = MemoryStore::new(NonZeroUsize::new(10).unwrap(), Duration::from_millis(0));

        store_secret(&mut store, None, None, None);

        thread::sleep(Duration::from_millis(1));

        let secret_value_output_read = store.get_secret_value(NAME, None, None);

        match secret_value_output_read {
            Err(SecretStoreError::CacheExpired(_)) => (),
            _ => panic!("Unexpected error"),
        }
    }

    #[test]
    fn memory_store_evicts_on_max_size() {
        let mut store = MemoryStore::new(NonZeroUsize::new(1).unwrap(), Duration::from_secs(1000));

        // Write a secret
        store_secret(&mut store, None, None, None);

        // Write a second secret
        store_secret(&mut store, Some("2"), None, None);

        let secret_value_output_read = store.get_secret_value(NAME, None, None);

        match secret_value_output_read {
            Err(SecretStoreError::ResourceNotFound) => (),
            Ok(r) => panic!("Unexpected value {:?}", r),
            Err(e) => panic!("Unexpected error: {}", e),
        }

        let second_secret_read =
            store.get_secret_value(format!("{}{}", NAME, "2").as_str(), None, None);

        if let Err(e) = second_secret_read {
            panic!("Unexpected error: {}", e)
        }
    }

    #[test]
    fn memory_store_read_both_version_id_and_stage_succeeds() {
        let mut store = MemoryStore::default();

        store_secret(
            &mut store,
            None,
            Some(VERSION_ID.to_string()),
            Some("AWSCURRENT".to_string()),
        );

        match store.get_secret_value(NAME, Some(VERSION_ID), Some("AWSCURRENT")) {
            Ok(_) => (),
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }

    #[test]
    fn memory_store_read_non_existent_version_stage_fails() {
        let mut store = MemoryStore::default();

        store_secret(&mut store, None, None, None);

        match store.get_secret_value(NAME, None, Some("NONEXISTENTSTAGE")) {
            Err(SecretStoreError::ResourceNotFound) => (),
            Ok(r) => panic!("Expected error, got {:?}", r),
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }
}
