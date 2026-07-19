use thiserror::Error;

/// Erreur unifiée de l'ensemble du projet Helios.
#[derive(Debug, Error)]
pub enum HeliosError {
    #[error("erreur de configuration : {0}")]
    Config(String),

    #[error("erreur du pare-feu : {0}")]
    Firewall(String),

    #[error("erreur de mise à jour : {0}")]
    Update(String),

    #[error("transition d'état invalide : {0}")]
    State(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, HeliosError>;
