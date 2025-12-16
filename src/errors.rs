use thiserror::Error;

#[derive(Debug, Error)]
pub enum IamError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),

    #[error("hashing error: {0}")]
    Hash(String),

    #[error("email sending error: {0}")]
    Email(String),

    #[error("account not found")]
    AccountNotFound,

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("email not verified")]
    EmailNotVerified,

    #[error("invalid verification code")]
    InvalidVerificationCode,

    #[error("verification code expired or already used")]
    VerificationCodeExpired,

    #[error("token not found")]
    TokenNotFound,

    #[error("token expired")]
    TokenExpired,

    #[error("token revoked")]
    TokenRevoked,

    #[error("password is too weak: {0}")]
    WeakPassword(String),

    #[error("email already verified")]
    EmailAlreadyVerified,

    #[error("lock acquisition timeout")]
    LockTimeout,

    #[error("refresh token double usage detected - token may be compromised")]
    TokenReuseDetected,

    #[error("invalid OAuth token")]
    InvalidOAuthToken,

    #[error("OAuth account email not verified")]
    OAuthEmailNotVerified,

    #[error("account has different authentication type")]
    AuthTypeMismatch,
}

