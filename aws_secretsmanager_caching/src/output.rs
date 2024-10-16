use aws_sdk_secretsmanager::operation::get_secret_value::GetSecretValueOutput;
use aws_smithy_types::base64;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{serde_as, DeserializeAs, SerializeAs, TimestampSecondsWithFrac};
use std::convert::TryFrom;
use std::time::SystemTime;

/// Exhaustive structure to store the secret value
///
/// We tried to De/Serialize the remote types using <https://serde.rs/remote-derive.html> but couldn't as the remote types are non_exhaustive,
/// which is a Rust limitation. We can remove this when aws sdk implements De/Serialize trait for the types.
#[serde_as]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct GetSecretValueOutputDef {
    /// The ARN of the secret.
    #[serde(rename(serialize = "ARN"))]
    pub arn: std::option::Option<std::string::String>,

    /// The friendly name of the secret.
    pub name: std::option::Option<std::string::String>,

    /// The unique identifier of this version of the secret.
    pub version_id: std::option::Option<std::string::String>,

    /// The decrypted secret value, if the secret value was originally provided as a string or through the Secrets Manager console.
    /// If this secret was created by using the console, then Secrets Manager stores the information as a JSON structure of key/value pairs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_string: std::option::Option<std::string::String>,

    /// Decrypted secret binary, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_binary: std::option::Option<BlobDef>,

    /// A list of all of the staging labels currently attached to this version of the secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_stages: std::option::Option<std::vec::Vec<std::string::String>>,

    /// The date and time that this version of the secret was created. If you don't specify which version in <code>VersionId</code> or <code>VersionStage</code>, then Secrets Manager uses the <code>AWSCURRENT</code> version.
    #[serde_as(as = "Option<TimestampSecondsWithFrac<String>>")]
    pub created_date: std::option::Option<SystemTime>,
}

impl GetSecretValueOutputDef {
    /// Converts GetSecretValueOutput to GetSecretValueOutputDef
    pub fn new(input: GetSecretValueOutput) -> Self {
        Self {
            arn: input.arn().map(|e| e.to_string()),
            name: input.name().map(|e| e.to_string()),
            version_id: input.version_id().map(|e| e.to_string()),
            secret_string: input.secret_string().map(|e| e.to_string()),
            secret_binary: input
                .secret_binary()
                .map(|e| BlobDef::new(e.clone().into_inner())),
            created_date: input
                .created_date()
                .and_then(|x| SystemTime::try_from(*x).ok()),
            version_stages: input.version_stages,
        }
    }
}

impl From<GetSecretValueOutput> for GetSecretValueOutputDef {
    fn from(input: GetSecretValueOutput) -> Self {
        Self::new(input)
    }
}

/// Copy of the remote AWS SDK Blob type.
#[serde_as]
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone, Deserialize)]
pub struct BlobDef {
    /// Binary content
    pub inner: Vec<u8>,
}

impl BlobDef {
    /// Creates a new blob from the given `input`.
    pub fn new(input: Vec<u8>) -> Self {
        BlobDef { inner: input }
    }

    /// Consumes the `Blob` and returns a `Vec<u8>` with its contents.
    pub fn into_inner(self) -> Vec<u8> {
        self.inner
    }
}

impl Serialize for BlobDef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode(self.clone().into_inner()))
    }
}

/// Copy of the remote aws_smithy_types::DateTime type.
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
#[serde(remote = "::aws_smithy_types::DateTime")]
pub struct DateTimeDef {
    #[serde(getter = "::aws_smithy_types::DateTime::secs")]
    seconds: i64,
    #[serde(getter = "::aws_smithy_types::DateTime::subsec_nanos")]
    subsecond_nanos: u32,
}

impl SerializeAs<::aws_smithy_types::DateTime> for DateTimeDef {
    fn serialize_as<S>(
        source: &::aws_smithy_types::DateTime,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        DateTimeDef::serialize(source, serializer)
    }
}

impl<'de> DeserializeAs<'de, ::aws_smithy_types::DateTime> for DateTimeDef {
    fn deserialize_as<D>(deserializer: D) -> Result<::aws_smithy_types::DateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        DateTimeDef::deserialize(deserializer)
    }
}

impl From<DateTimeDef> for ::aws_smithy_types::DateTime {
    fn from(def: DateTimeDef) -> ::aws_smithy_types::DateTime {
        ::aws_smithy_types::DateTime::from_secs_and_nanos(def.seconds, def.subsecond_nanos)
    }
}
