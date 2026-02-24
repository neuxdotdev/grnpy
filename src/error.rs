use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Insufficient entropy: {0}")]
    Entropy(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Invalid length: expected between {min} and {max}, got {actual}")]
    InvalidLength {
        min: usize,
        max: usize,
        actual: usize,
    },

    #[error("Invalid character set: {0}")]
    InvalidCharset(String),

    #[error("Password error: {0}")]
    Password(String),

    #[error("Bcrypt error: {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),

    #[error("PIN must be numeric and of length {len}")]
    PinFormat { len: usize },

    #[error("JWT error: {0}")]
    Jwt(String),

    #[error("API key error: {0}")]
    ApiKey(String),

    #[error("Internal error: {msg}")]
    Internal { msg: String },
}

pub type Result<T> = std::result::Result<T, Error>;
