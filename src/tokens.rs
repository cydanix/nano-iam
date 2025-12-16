use chrono::{Duration, Utc};
use rand::{distributions::Alphanumeric, Rng};
use uuid::Uuid;

use crate::models::{Token, TokenPair, TokenType};

pub fn generate_token(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

pub fn generate_token_pair(
    access_ttl: Duration,
    refresh_ttl: Duration,
) -> TokenPair {
    let now = Utc::now();
    let access_expires_at = now + access_ttl;
    let refresh_expires_at = now + refresh_ttl;
    
    TokenPair {
        access_token: Token {
            id: Uuid::nil(),
            account_id: Uuid::nil(),
            token: generate_token(64),
            token_type: TokenType::Access,
            expires_at: access_expires_at,
            created_at: now,
            revoked_at: None,
            root_token: None,
            usage: 0,
        },
        access_token_expires_at: access_expires_at,
        refresh_token: Token {
            id: Uuid::nil(),
            account_id: Uuid::nil(),
            token: generate_token(64),
            token_type: TokenType::Refresh,
            expires_at: refresh_expires_at,
            created_at: now,
            revoked_at: None,
            root_token: None,
            usage: 0,
        },
        refresh_token_expires_at: refresh_expires_at,
    }
}

