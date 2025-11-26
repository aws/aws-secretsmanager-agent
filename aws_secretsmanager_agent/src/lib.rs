// Library interface for the AWS Secrets Manager Agent
// This exposes internal modules for testing and fuzzing purposes

pub mod cache_manager;
pub mod config;
pub mod constants;
pub mod error;
pub mod logging;
pub mod parse;
pub mod server;
pub mod utils;

// Re-export key types and functions for fuzzing
pub use parse::GSVQuery;
pub use utils::get_token;
