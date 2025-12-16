use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type AccountId = Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Account {
    pub id: AccountId,
    pub email: String,
    pub password_hash: String,
    pub email_verified: bool,
    pub auth_type: AuthType,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EmailVerification {
    pub id: Uuid,
    pub account_id: AccountId,
    pub code: String,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Token {
    pub id: Uuid,
    pub account_id: AccountId,
    pub token: String,
    pub token_type: TokenType,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub root_token: Option<String>,
    pub usage: i64,
}

impl Token {
    /// Create a new Token with just the token value (for TokenPair)
    /// Database fields will be set to default/empty values
    pub fn new(value: String) -> Self {
        Self {
            id: Uuid::nil(),
            account_id: Uuid::nil(),
            token: value,
            token_type: TokenType::Access, // Default, not used for TokenPair
            expires_at: Utc::now(),
            created_at: Utc::now(),
            revoked_at: None,
            root_token: None,
            usage: 0,
        }
    }

    /// Get the token value as a string slice (for frontend use)
    pub fn as_str(&self) -> &str {
        &self.token
    }

    /// Get the token value as an owned String
    pub fn to_string(&self) -> String {
        self.token.clone()
    }
}

impl PartialEq for Token {
    fn eq(&self, other: &Self) -> bool {
        self.token == other.token
    }
}

impl Eq for Token {}

#[derive(Debug, Clone)]
pub struct TokenPair {
    pub access_token: Token,
    pub access_token_expires_at: DateTime<Utc>,
    pub refresh_token: Token,
    pub refresh_token_expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, sqlx::Type, PartialEq, Eq)]
#[sqlx(type_name = "token_type", rename_all = "lowercase")]
pub enum TokenType {
    Access,
    Refresh,
}

#[derive(Debug, Clone, Copy, sqlx::Type, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[sqlx(type_name = "auth_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    Email,
    Google,
}

