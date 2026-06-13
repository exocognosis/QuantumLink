use thiserror::Error;

pub type Result<T> = std::result::Result<T, QlinkError>;

#[derive(Debug, Error)]
pub enum QlinkError {
    #[error("invalid key material: {0}")]
    InvalidKey(String),

    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("route parse error: {0}")]
    Route(String),

    #[error("record expired")]
    RecordExpired,

    #[error("signature verification failed")]
    SignatureVerification,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
