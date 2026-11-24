use std::sync::{OnceLock, RwLock};
use tracing_subscriber::Registry;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload::Handle;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    #[error("Parse filter error: {0}")]
    ParseFilter(#[from] tracing_subscriber::filter::ParseError),
    #[error("Reload error: {0}")]
    Reload(String),
}

type ReloadHandle = Handle<EnvFilter, Registry>;

static LOG_HANDLE: OnceLock<ReloadHandle> = OnceLock::new();
static CURRENT_LEVEL: RwLock<String> = RwLock::new(String::new());

pub struct LoggingManager;

impl LoggingManager {
    /// Initializes logging system in-memory with the given initial filter.
    /// If no initial filter is provided, defaults to "info".
    pub fn init(initial_level: Option<&str>) -> Result<(), LoggingError> {
        let filter_str = initial_level.unwrap_or("info");

        {
            let mut curr = CURRENT_LEVEL.write().unwrap();
            *curr = filter_str.to_string();
        }

        let filter = EnvFilter::try_new(filter_str)?;
        let (filter_layer, reload_handle) = tracing_subscriber::reload::Layer::new(filter);

        let _ = LOG_HANDLE.set(reload_handle);

        let subscriber = tracing_subscriber::registry()
            .with(filter_layer)
            .with(tracing_subscriber::fmt::layer());

        let _ = subscriber.try_init();

        Ok(())
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
    fn test_dynamic_logging_level_in_memory() {
        LoggingManager::init(Some("info")).unwrap();
        assert_eq!(LoggingManager::get_level(), "info");

        // Change level dynamically
        LoggingManager::set_level("debug").unwrap();
        assert_eq!(LoggingManager::get_level(), "debug");

        // Change level with module filter syntax
        LoggingManager::set_level("pds=trace,warn").unwrap();
        assert_eq!(LoggingManager::get_level(), "pds=trace,warn");
    }
}
