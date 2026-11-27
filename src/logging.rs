//! Provides logging management and dynamic filter reconfiguration.

use std::sync::{OnceLock, RwLock};
use tracing_subscriber::Registry;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload::Handle;
use tracing_subscriber::util::SubscriberInitExt;

/// Errors produced during logging initialization and filter reload operations.
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    /// Occurs when a filter directive string is invalid.
    #[error("Parse filter error: {0}")]
    ParseFilter(#[from] tracing_subscriber::filter::ParseError),
    /// Occurs when reloading the log subscriber fails.
    #[error("Reload error: {0}")]
    Reload(String),
}

type ReloadHandle = Handle<EnvFilter, Registry>;

static LOG_HANDLE: OnceLock<ReloadHandle> = OnceLock::new();
static CURRENT_LEVEL: RwLock<String> = RwLock::new(String::new());

/// Controls tracing initialization and runtime log level updates.
pub struct LoggingManager;

impl LoggingManager {
    /// Initializes logging system with a custom tracing layer (e.g. Android Logcat, OpenTelemetry).
    pub fn init_custom<L>(initial_level: Option<&str>, layer: L) -> Result<(), LoggingError>
    where
        L: tracing_subscriber::Layer<Registry> + Send + Sync + 'static,
    {
        let filter_str = initial_level.unwrap_or("info");

        {
            let mut curr = CURRENT_LEVEL.write().unwrap();
            *curr = filter_str.to_string();
        }

        let filter = EnvFilter::try_new(filter_str)?;
        let (filter_layer, reload_handle) = tracing_subscriber::reload::Layer::new(filter);

        let _ = LOG_HANDLE.set(reload_handle);

        let subscriber = tracing_subscriber::registry().with(layer.with_filter(filter_layer));

        let _ = subscriber.try_init();

        Ok(())
    }

    /// Initializes logging system in-memory using the default fmt::layer() (stdout).
    /// If no initial filter is provided, defaults to "info".
    pub fn init(initial_level: Option<&str>) -> Result<(), LoggingError> {
        Self::init_custom(initial_level, tracing_subscriber::fmt::layer())
    }

    /// Returns current log level / filter string.
    pub fn get_level() -> String {
        let curr = CURRENT_LEVEL.read().unwrap();
        if curr.is_empty() {
            "info".to_string()
        } else {
            curr.clone()
        }
    }

    /// Dynamically reloads logging level in memory.
    pub fn set_level(new_level: &str) -> Result<(), LoggingError> {
        let new_filter = EnvFilter::try_new(new_level)?;

        if let Some(handle) = LOG_HANDLE.get() {
            handle
                .reload(new_filter)
                .map_err(|e| LoggingError::Reload(e.to_string()))?;
        }

        {
            let mut curr = CURRENT_LEVEL.write().unwrap();
            *curr = new_level.to_string();
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_logging_level_and_custom_layer() {
        // Test custom layer delegation
        let custom_layer = tracing_subscriber::fmt::layer().compact();
        let result = LoggingManager::init_custom(Some("info"), custom_layer);
        assert!(result.is_ok());

        assert_eq!(LoggingManager::get_level(), "info");

        // Change level dynamically
        LoggingManager::set_level("debug").unwrap();
        assert_eq!(LoggingManager::get_level(), "debug");

        // Change level with module filter syntax
        LoggingManager::set_level("pds=trace,warn").unwrap();
        assert_eq!(LoggingManager::get_level(), "pds=trace,warn");
    }
}
