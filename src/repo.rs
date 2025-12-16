use chrono::{DateTime, Utc};
use sqlx::{Pool, Postgres};
use uuid::Uuid;
use tracing::{error, warn};

use crate::errors::IamError;
use crate::models::{Account, AccountId, EmailVerification, Token, TokenType};

pub type PgPool = Pool<Postgres>;

pub struct Repo {
    pub pool: PgPool,
}

impl Repo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_account(
        &self,
        email: &str,
        password_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Account, IamError> {
        let rec = sqlx::query_as::<_, Account>(
            r#"
insert into accounts (id, email, password_hash, email_verified, created_at, updated_at)
values ($1, $2, $3, false, $4, $4)
returning id, email, password_hash, email_verified, created_at, updated_at
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(email)
        .bind(password_hash)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            error!(email = %email, error = %e, "Database error creating account");
            IamError::from(e)
        })?;

        Ok(rec)
    }

    pub async fn find_account_by_email(
        &self,
        email: &str,
    ) -> Result<Option<Account>, IamError> {
        let rec = sqlx::query_as::<_, Account>(
            r#"
select id, email, password_hash, email_verified, created_at, updated_at
from accounts
where email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            error!(email = %email, error = %e, "Database error finding account by email");
            IamError::from(e)
        })?;

        Ok(rec)
    }

    pub async fn find_account_by_id(
        &self,
        account_id: AccountId,
    ) -> Result<Option<Account>, IamError> {
        let rec = sqlx::query_as::<_, Account>(
            r#"
select id, email, password_hash, email_verified, created_at, updated_at
from accounts
where id = $1
            "#,
        )
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            error!(account_id = %account_id, error = %e, "Database error finding account by id");
            IamError::from(e)
        })?;

        Ok(rec)
    }

    pub async fn mark_email_verified(
        &self,
        account_id: AccountId,
        now: DateTime<Utc>,
    ) -> Result<(), IamError> {
        sqlx::query(
            r#"
update accounts
set email_verified = true,
    updated_at = $2
where id = $1
            "#,
        )
        .bind(account_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(account_id = %account_id, error = %e, "Database error marking email as verified");
            IamError::from(e)
        })?;

        Ok(())
    }

    pub async fn create_email_verification(
        &self,
        account_id: AccountId,
        code: &str,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<EmailVerification, IamError> {
        let rec = sqlx::query_as::<_, EmailVerification>(
            r#"
insert into email_verifications (id, account_id, code, expires_at, consumed_at, created_at)
values ($1, $2, $3, $4, null, $5)
returning id, account_id, code, expires_at, consumed_at, created_at
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(account_id)
        .bind(code)
        .bind(expires_at)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            error!(account_id = %account_id, error = %e, "Database error creating email verification");
            IamError::from(e)
        })?;

        Ok(rec)
    }

    pub async fn consume_email_verification(
        &self,
        account_id: AccountId,
        code: &str,
        now: DateTime<Utc>,
    ) -> Result<(), IamError> {
        let rec = sqlx::query(
            r#"
update email_verifications
set consumed_at = $3
where account_id = $1
  and code = $2
  and consumed_at is null
  and expires_at > $3
returning id
            "#,
        )
        .bind(account_id)
        .bind(code)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            error!(account_id = %account_id, error = %e, "Database error consuming email verification");
            IamError::from(e)
        })?;

        if rec.is_none() {
            warn!(account_id = %account_id, "Verification code expired or already used");
            return Err(IamError::VerificationCodeExpired);
        }

        Ok(())
    }

    pub async fn insert_token(
        &self,
        account_id: AccountId,
        token: &str,
        token_type: TokenType,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<Token, IamError> {
        let rec = sqlx::query_as::<_, Token>(
            r#"
insert into tokens (id, account_id, token, token_type, expires_at, created_at, revoked_at)
values ($1, $2, $3, $4, $5, $6, null)
returning id, account_id, token, token_type, expires_at, created_at, revoked_at
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(account_id)
        .bind(token)
        .bind(token_type)
        .bind(expires_at)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            error!(account_id = %account_id, token_type = ?token_type, error = %e, "Database error inserting token");
            IamError::from(e)
        })?;

        Ok(rec)
    }

    pub async fn find_valid_token(
        &self,
        token: &str,
        token_type: TokenType,
        now: DateTime<Utc>,
    ) -> Result<Token, IamError> {
        let rec = sqlx::query_as::<_, Token>(
            r#"
select id, account_id, token, token_type, expires_at, created_at, revoked_at
from tokens
where token = $1
  and token_type = $2
  and revoked_at is null
  and expires_at > $3
            "#,
        )
        .bind(token)
        .bind(token_type)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            error!(token_type = ?token_type, error = %e, "Database error finding token");
            IamError::from(e)
        })?;

        match rec {
            Some(row) => Ok(row),
            None => {
                warn!(token_type = ?token_type, "Token not found or expired");
                Err(IamError::TokenExpired)
            }
        }
    }

    pub async fn revoke_token(
        &self,
        token: &str,
        token_type: TokenType,
        now: DateTime<Utc>,
    ) -> Result<(), IamError> {
        sqlx::query(
            r#"
update tokens
set revoked_at = $3
where token = $1
  and token_type = $2
  and revoked_at is null
            "#,
        )
        .bind(token)
        .bind(token_type)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(token_type = ?token_type, error = %e, "Database error revoking token");
            IamError::from(e)
        })?;

        Ok(())
    }

    pub async fn delete_account(
        &self,
        account_id: AccountId,
    ) -> Result<(), IamError> {
        sqlx::query(
            r#"
delete from accounts
where id = $1
            "#,
        )
        .bind(account_id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(account_id = %account_id, error = %e, "Database error deleting account");
            IamError::from(e)
        })?;

        Ok(())
    }

    pub async fn revoke_all_tokens(
        &self,
        account_id: AccountId,
        now: DateTime<Utc>,
    ) -> Result<(), IamError> {
        sqlx::query(
            r#"
update tokens
set revoked_at = $2
where account_id = $1
  and revoked_at is null
            "#,
        )
        .bind(account_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(account_id = %account_id, error = %e, "Database error revoking all tokens");
            IamError::from(e)
        })?;

        Ok(())
    }

    pub async fn update_password_hash(
        &self,
        account_id: AccountId,
        password_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<(), IamError> {
        sqlx::query(
            r#"
update accounts
set password_hash = $2,
    updated_at = $3
where id = $1
            "#,
        )
        .bind(account_id)
        .bind(password_hash)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(account_id = %account_id, error = %e, "Database error updating password");
            IamError::from(e)
        })?;

        Ok(())
    }

    pub async fn find_email_verification_by_account(
        &self,
        account_id: AccountId,
    ) -> Result<Option<EmailVerification>, IamError> {
        let rec = sqlx::query_as::<_, EmailVerification>(
            r#"
select id, account_id, code, expires_at, consumed_at, created_at
from email_verifications
where account_id = $1
  and consumed_at is null
order by created_at desc
limit 1
            "#,
        )
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            error!(account_id = %account_id, error = %e, "Database error finding email verification");
            IamError::from(e)
        })?;

        Ok(rec)
    }
}

