// Library interface for the AWS Secrets Manager Agent
// Only exposes modules needed for public API and testing

pub mod config;
pub mod error;

// Internal modules exposed only for testing and fuzzing
#[doc(hidden)]
pub mod internal {
    pub mod cache_manager {
        pub use crate::cache_manager::*;
    }
    pub mod constants {
        pub use crate::constants::*;
    }
    pub mod logging {
        pub use crate::logging::*;
    }
    pub mod parse {
        pub use crate::parse::*;
    }
    pub mod server {
        pub use crate::server::*;
    }
    pub mod utils {
        pub use crate::utils::*;
    }
}

// Private modules
mod cache_manager;
mod constants;
mod logging;
mod parse;
mod server;
mod utils;
