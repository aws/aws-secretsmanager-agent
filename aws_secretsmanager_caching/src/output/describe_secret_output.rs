use std::time::SystemTime;

use aws_sdk_secretsmanager::{
    operation::describe_secret::DescribeSecretOutput,
    types::{ReplicationStatusType, StatusType, Tag},
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, TimestampSecondsWithFrac};

/// Structure to store the secret details
#[serde_as]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct DescribeSecretOutputDef {
    /// The ARN of the secret.
    #[serde(rename(serialize = "ARN"))]
    pub arn: Option<String>,

    /// The name of the secret.
    pub name: Option<String>,

    /// The description of the secret.
    pub description: Option<String>,

    /// The key ID or alias ARN of the KMS key that Secrets Manager uses to encrypt the secret value. If the secret is encrypted with the Amazon Web Services managed key <code>aws/secretsmanager</code>, this field is omitted. Secrets created using the console use an KMS key ID.
    pub kms_key_id: Option<String>,

    /// Specifies whether automatic rotation is turned on for this secret.
    /// To turn on rotation, use <code>RotateSecret</code>. To turn off rotation, use <code>CancelRotateSecret</code>.
    pub rotation_enabled: Option<bool>,

    /// The ARN of the Lambda function that Secrets Manager invokes to rotate the secret.
    pub rotation_lambda_arn: Option<String>,

    // Todo: Add support for this; skipping as not in scope for Ragnarok
    // pub rotation_rules: Option<crate::types::RotationRulesType>,
    /// The last date and time that Secrets Manager rotated the secret. If the secret isn't configured for rotation, Secrets Manager returns null.
    #[serde_as(as = "Option<TimestampSecondsWithFrac<String>>")]
    pub last_rotated_date: Option<SystemTime>,

    /// The last date and time that this secret was modified in any way.
    #[serde_as(as = "Option<TimestampSecondsWithFrac<String>>")]
    pub last_changed_date: Option<SystemTime>,

    /// The date that the secret was last accessed in the Region. This field is omitted if the secret has never been retrieved in the Region.
    #[serde_as(as = "Option<TimestampSecondsWithFrac<String>>")]
    pub last_accessed_date: Option<SystemTime>,

    /// The date the secret is scheduled for deletion. If it is not scheduled for deletion, this field is omitted. When you delete a secret, Secrets Manager requires a recovery window of at least 7 days before deleting the secret. Some time after the deleted date, Secrets Manager deletes the secret, including all of its versions.
    /// If a secret is scheduled for deletion, then its details, including the encrypted secret value, is not accessible. To cancel a scheduled deletion and restore access to the secret, use <code>RestoreSecret</code>.
    #[serde_as(as = "Option<TimestampSecondsWithFrac<String>>")]
    pub deleted_date: Option<SystemTime>,

    /// The next rotation is scheduled to occur on or before this date. If the secret isn't configured for rotation, Secrets Manager returns null.
    #[serde_as(as = "Option<TimestampSecondsWithFrac<String>>")]
    pub next_rotation_date: Option<SystemTime>,

    /// The list of tags attached to the secret. To add tags to a secret, use <code>TagResource</code>. To remove tags, use <code>UntagResource</code>.
    pub tags: Option<Vec<TagDef>>,

    /// A list of the versions of the secret that have staging labels attached. Versions that don't have staging labels are considered deprecated and Secrets Manager can delete them.
    /// Secrets Manager uses staging labels to indicate the status of a secret version during rotation. The three staging labels for rotation are:
    /// <ul>
    /// <li>  <code>AWSCURRENT</code>, which indicates the current version of the secret. </li>
    /// <li>  <code>AWSPENDING</code>, which indicates the version of the secret that contains new secret information that will become the next current version when rotation finishes. During rotation, Secrets Manager creates an <code>AWSPENDING</code> version ID before creating the new secret version. To check if a secret version exists, call <code>GetSecretValue</code>. </li>
    /// <li>  <code>AWSPREVIOUS</code>, which indicates the previous current version of the secret. You can use this as the <i>last known good</i> version. </li>
    /// </ul>
    /// For more information about rotation and staging labels, see <a href="https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_how.html">How rotation works</a>.
    pub version_ids_to_stages: Option<::std::collections::HashMap<String, Vec<String>>>,

    /// The ID of the service that created this secret. For more information, see <a href="https://docs.aws.amazon.com/secretsmanager/latest/userguide/service-linked-secrets.html">Secrets managed by other Amazon Web Services services</a>.
    pub owning_service: Option<String>,

    /// The date the secret was created.
    #[serde_as(as = "Option<TimestampSecondsWithFrac<String>>")]
    pub created_date: Option<SystemTime>,

    // Todo: Add support for this; skipping as not in scope for Ragnarok
    // pub replication_status:
    // Option<::std::vec::Vec<crate::types::ReplicationStatusType>>,
    /// The Region the secret is in. If a secret is replicated to other Regions, the replicas are listed in <code>ReplicationStatus</code>.
    pub primary_region: Option<String>,
    /// <p>A list of the replicas of this secret and their status:</p>
    /// <ul>
    /// <li>
    /// <p><code>Failed</code>, which indicates that the replica was not created.</p></li>
    /// <li>
    /// <p><code>InProgress</code>, which indicates that Secrets Manager is in the process of creating the replica.</p></li>
    /// <li>
    /// <p><code>InSync</code>, which indicates that the replica was created.</p></li>
    /// </ul>
    pub replication_status: Option<Vec<ReplicationStatusTypeDef>>,
}

impl DescribeSecretOutputDef {
    /// Converts DescribeSecretOutput to DescribeSecretOutputDef
    pub fn new(describe: DescribeSecretOutput) -> Self {
        DescribeSecretOutputDef {
            arn: describe.arn,
            name: describe.name,
            description: describe.description,
            kms_key_id: describe.kms_key_id,
            rotation_enabled: describe.rotation_enabled,
            rotation_lambda_arn: describe.rotation_lambda_arn,
            last_rotated_date: describe.last_rotated_date.map(|i| i.try_into().unwrap()),
            last_changed_date: describe.last_changed_date.map(|i| i.try_into().unwrap()),
            last_accessed_date: describe.last_accessed_date.map(|i| i.try_into().unwrap()),
            deleted_date: describe.deleted_date.map(|i| i.try_into().unwrap()),
            next_rotation_date: describe.next_rotation_date.map(|i| i.try_into().unwrap()),
            tags: describe
                .tags
                .map(|o| o.iter().map(|tag| tag.into()).collect()),
            version_ids_to_stages: describe.version_ids_to_stages,
            owning_service: describe.owning_service,
            created_date: describe.created_date.map(|i| i.try_into().unwrap()),
            replication_status: describe.replication_status.map(|replication_status| {
                replication_status
                    .iter()
                    .map(|status| status.into())
                    .collect()
            }),
            primary_region: describe.primary_region,
        }
    }
}

/// Copy of the remote aws_sdk_secretsmanager::types::DateTime type.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TagDef {
    /// The key identifier, or name, of the tag.
    pub key: Option<String>,

    /// The string value associated with the key of the tag.
    pub value: Option<String>,
}

impl From<&Tag> for TagDef {
    fn from(value: &Tag) -> Self {
        TagDef {
            key: value.key.clone(),
            value: value.value.clone(),
        }
    }
}

#[serde_as]
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
/// Replication status type
pub struct ReplicationStatusTypeDef {
    /// <p>The Region where replication occurs.</p>
    pub region: Option<String>,
    /// <p>Can be an <code>ARN</code>, <code>Key ID</code>, or <code>Alias</code>.</p>
    pub kms_key_id: Option<String>,
    /// <p>The status can be <code>InProgress</code>, <code>Failed</code>, or <code>InSync</code>.</p>
    pub status: Option<StatusTypeDef>,
    /// <p>Status message such as "<i>Secret with this name already exists in this region</i>".</p>
    pub status_message: Option<String>,
    /// <p>The date that the secret was last accessed in the Region. This field is omitted if the secret has never been retrieved in the Region.</p>
    pub last_accessed_date: Option<SystemTime>,
}

impl From<ReplicationStatusTypeDef> for ReplicationStatusType {
    fn from(value: ReplicationStatusTypeDef) -> Self {
        ReplicationStatusType::builder()
            .set_region(value.region)
            .set_kms_key_id(value.kms_key_id)
            .set_status(value.status.map(Into::into))
            .set_last_accessed_date(value.last_accessed_date.map(Into::into))
            .set_status_message(value.status_message)
            .build()
    }
}

impl From<&ReplicationStatusType> for ReplicationStatusTypeDef {
    fn from(value: &ReplicationStatusType) -> Self {
        ReplicationStatusTypeDef {
            region: value.region().map(String::from),
            kms_key_id: value.kms_key_id().map(String::from),
            status: value.status().map(Into::into),
            status_message: value.status_message().map(String::from),
            last_accessed_date: value.last_accessed_date().map(|i| (*i).try_into().unwrap()),
        }
    }
}

#[serde_as]
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Debug, Hash, Serialize, Deserialize)]
/// Status type
pub enum StatusTypeDef {
    #[allow(missing_docs)] // documentation missing in model
    Failed,
    #[allow(missing_docs)] // documentation missing in model
    InProgress,
    #[allow(missing_docs)] // documentation missing in model
    InSync,
}

impl From<StatusTypeDef> for StatusType {
    fn from(value: StatusTypeDef) -> Self {
        match value {
            StatusTypeDef::Failed => StatusType::Failed,
            StatusTypeDef::InProgress => StatusType::InProgress,
            StatusTypeDef::InSync => StatusType::InSync,
        }
    }
}

impl From<&StatusType> for StatusTypeDef {
    fn from(value: &StatusType) -> Self {
        match value {
            StatusType::Failed => StatusTypeDef::Failed,
            StatusType::InProgress => StatusTypeDef::InProgress,
            StatusType::InSync => StatusTypeDef::InSync,
            _ => panic!("Invalid value for StatusTypeDef: {}", value),
        }
    }
}

impl From<DescribeSecretOutput> for DescribeSecretOutputDef {
    fn from(input: DescribeSecretOutput) -> Self {
        Self::new(input)
    }
}
