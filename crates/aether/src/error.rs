use thiserror::Error;

/// Unified error type for the whole Helios project.
#[derive(Debug, Error)]
pub enum HeliosError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("firewall error: {0}")]
    Firewall(String),

    #[error("update error: {0}")]
    Update(String),

    #[error("invalid state transition: {0}")]
    State(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, HeliosError>;
