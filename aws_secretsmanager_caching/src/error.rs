use aws_sdk_secretsmanager::operation::describe_secret::DescribeSecretError;
use aws_smithy_runtime_api::client::{orchestrator::HttpResponse, result::SdkError};

pub(crate) fn is_transient_error(e: &SdkError<DescribeSecretError, HttpResponse>) -> bool {
    match e {
        SdkError::TimeoutError(_)
        | SdkError::ResponseError(_)
        | SdkError::DispatchFailure(_)
        | SdkError::ConstructionFailure(_) => true,
        _ => false,
    }
}
