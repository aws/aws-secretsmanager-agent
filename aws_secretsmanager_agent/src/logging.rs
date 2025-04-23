use crate::config::LogLevel;
use log::{info, LevelFilter, SetLoggerError};
use log4rs::append::console::ConsoleAppender;
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::config::{Appender, Root};
use log4rs::Config;
use std::sync::Once;

impl From<LogLevel> for LevelFilter {
    fn from(log_level: LogLevel) -> LevelFilter {
        match log_level {
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Error => LevelFilter::Error,
            LogLevel::None => LevelFilter::Off,
        }
    }
}

const LOG_FILE_PATH: &str = "./logs/secrets_manager_agent.log";
const LOG_ARCHIVE_FILE_PATH_PATTERN: &str = "./logs/archive/secrets_manager_agent_{}.gz";
const MAX_LOG_ARCHIVE_FILES: u32 = 5;
const BYTES_PER_MB: u64 = 1024 * 1024;
const MAX_ALLOWED_LOG_SIZE_IN_MB: u64 = 10;

#[doc(hidden)]
static STARTUP: Once = Once::new();

/// Initializes file based logging for the daemon.
///
/// # Arguments
///
/// * `log_level` - The log level to report.
/// * `log_to_file` - Whether to log to a file or stdout/stderr.
///
/// # Returns
///
/// * `Ok(())` - If no errors are encountered.
/// * `Err(Error)` - For errors initializing the log.
pub fn init_logger(
    log_level: LogLevel,
    log_to_file: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (log_config, logger_type) = match log_to_file {
        true => {
            let file_appender = "FILE_APPENDER";

            let fixed_window_roller = FixedWindowRoller::builder()
                .build(LOG_ARCHIVE_FILE_PATH_PATTERN, MAX_LOG_ARCHIVE_FILES)?;
            let fixed_window_roller = Box::new(fixed_window_roller);

            let file_size_trigger =
                Box::new(SizeTrigger::new(MAX_ALLOWED_LOG_SIZE_IN_MB * BYTES_PER_MB));
            let compound_policy =
                Box::new(CompoundPolicy::new(file_size_trigger, fixed_window_roller));

            let rolling_file_appender =
                RollingFileAppender::builder().build(LOG_FILE_PATH, compound_policy)?;

            (
                Config::builder()
                    .appender(
                        Appender::builder().build(file_appender, Box::new(rolling_file_appender)),
                    )
                    .build(
                        Root::builder()
                            .appender(file_appender)
                            .build(log_level.into()),
                    )?,
                "File",
            )
        }
        false => {
            let console_appender = "CONSOLE_APPENDER";

            (
                Config::builder()
                    .appender(Appender::builder().build(
                        console_appender,
                        Box::new(ConsoleAppender::builder().build()),
                    ))
                    .build(
                        Root::builder()
                            .appender(console_appender)
                            .build(log_level.into()),
                    )?,
                "Console",
            )
        }
    };

    // Don't initialize logging more than once in unit tests.
    let mut res: Option<SetLoggerError> = None;
    STARTUP.call_once(|| {
        if let Err(err) = log4rs::init_config(log_config) {
            res = Some(err);
        }
    });
    if let Some(err) = res {
        return Err(Box::new(err));
    }

    info!(
        "{} logger initialized with `{:?}` log level.",
        logger_type, log_level
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::config::LogLevel;
    use crate::logging::init_logger;
    use log::{debug, error, info, warn, LevelFilter};

    /// Tests that file logger is getting initialized without errors.
    #[test]
    fn test_init_file_logger() {
        init_logger(LogLevel::Info, true).unwrap();
        debug!("{:?}", "Debug log");
        error!("{:?}", "Error log");
        info!("{:?}", "Info log");
        warn!("{:?}", "Warn log");
    }

    /// Tests that console logger is getting initialized without errors.
    #[test]
    fn test_init_console_logger() {
        init_logger(LogLevel::Info, false).unwrap();
        debug!("{:?}", "Debug log");
        error!("{:?}", "Error log");
        info!("{:?}", "Info log");
        warn!("{:?}", "Warn log");
    }

    /// Tests that LogLevel is correctly getting converted to LevelFilter
    #[test]
    fn test_log_level_to_level_filter_conversion() {
        assert_eq!(
            <LogLevel as Into<LevelFilter>>::into(LogLevel::Debug),
            LevelFilter::Debug
        );
        assert_eq!(
            <LogLevel as Into<LevelFilter>>::into(LogLevel::Info),
            LevelFilter::Info
        );
        assert_eq!(
            <LogLevel as Into<LevelFilter>>::into(LogLevel::Warn),
            LevelFilter::Warn
        );
        assert_eq!(
            <LogLevel as Into<LevelFilter>>::into(LogLevel::Error),
            LevelFilter::Error
        );
        assert_eq!(
            <LogLevel as Into<LevelFilter>>::into(LogLevel::None),
            LevelFilter::Off
        );
    }
}
