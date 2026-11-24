use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};
use tracing_subscriber::Registry;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload::Handle;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Parse filter error: {0}")]
    ParseFilter(#[from] tracing_subscriber::filter::ParseError),
    #[error("Reload error: {0}")]
    Reload(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub log_level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
        }
    }
}

type ReloadHandle = Handle<EnvFilter, Registry>;

static LOG_HANDLE: OnceLock<ReloadHandle> = OnceLock::new();
static CONFIG_PATH: RwLock<Option<PathBuf>> = RwLock::new(None);
static CURRENT_LEVEL: RwLock<String> = RwLock::new(String::new());

pub struct LoggingManager;

impl LoggingManager {
    /// Initializes logging system with optional root config path.
    /// If config.json exists in root_dir, loads stored level. Otherwise defaults to "info".
    pub fn init(root_dir: Option<impl AsRef<Path>>) -> Result<(), LoggingError> {
        let (config_file, initial_filter_str) = if let Some(dir) = root_dir {
            let path = dir.as_ref().join("config.json");
            let level = if path.exists() {
                let data = fs::read_to_string(&path)?;
                let cfg: LoggingConfig = serde_json::from_str(&data).unwrap_or_default();
                cfg.log_level
            } else {
                "info".to_string()
            };
            (Some(path), level)
        } else {
            (None, "info".to_string())
        };

        if let Some(ref path) = config_file {
            let mut stored_path = CONFIG_PATH.write().unwrap();
            *stored_path = Some(path.clone());
        }

        {
            let mut curr = CURRENT_LEVEL.write().unwrap();
            *curr = initial_filter_str.clone();
        }

        let filter = EnvFilter::try_new(&initial_filter_str)?;
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

    /// Dynamically reloads logging level and persists to config.json if path configured.
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

        // Persist to disk if path configured
        let path_opt = CONFIG_PATH.read().unwrap().clone();
        if let Some(path) = path_opt {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let cfg = LoggingConfig {
                log_level: new_level.to_string(),
            };
            let json = serde_json::to_string_pretty(&cfg)?;
            fs::write(path, json)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_logging_level_and_persistence() {
        let temp_dir =
            std::env::temp_dir().join(format!("pds_log_test_{}", crate::id::BlobId::new()));
        fs::create_dir_all(&temp_dir).unwrap();

        LoggingManager::init(Some(&temp_dir)).unwrap();
        assert_eq!(LoggingManager::get_level(), "info");

        // Change level dynamically
        LoggingManager::set_level("debug").unwrap();
        assert_eq!(LoggingManager::get_level(), "debug");

        // Verify config.json on disk
        let config_path = temp_dir.join("config.json");
        assert!(config_path.exists());
        let content = fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("\"debug\""));

        // Change level again with module filter syntax
        LoggingManager::set_level("pds=trace,warn").unwrap();
        assert_eq!(LoggingManager::get_level(), "pds=trace,warn");
        let content2 = fs::read_to_string(&config_path).unwrap();
        assert!(content2.contains("\"pds=trace,warn\""));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
