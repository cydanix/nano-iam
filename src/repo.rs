use chrono::{DateTime, Utc};
use sqlx::{Pool, Postgres};
use uuid::Uuid;
use tracing::{error, warn, info, debug};

use crate::errors::IamError;
use crate::models::{Account, AccountId, AuthType, EmailVerification, Token, TokenType};
use crate::retry::retry;
use crate::locks::{LeaseLock, with_lock};

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
        auth_type: crate::models::AuthType,
        now: DateTime<Utc>,
    ) -> Result<Account, IamError> {
        let rec = sqlx::query_as::<_, Account>(
            r#"
insert into accounts (id, email, password_hash, email_verified, auth_type, created_at, updated_at, deleted_at)
values ($1, $2, $3, $4, $5, $6, $6, null)
returning id, email, password_hash, email_verified, auth_type, created_at, updated_at, deleted_at
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(email)
        .bind(password_hash)
        .bind(matches!(auth_type, AuthType::Google)) // Google accounts are pre-verified
        .bind(auth_type)
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
select id, email, password_hash, email_verified, auth_type, created_at, updated_at, deleted_at
from accounts
where email = $1
  and deleted_at is null
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

    pub async fn find_account_by_email_including_deleted(
        &self,
        email: &str,
    ) -> Result<Option<Account>, IamError> {
        let rec = sqlx::query_as::<_, Account>(
            r#"
select id, email, password_hash, email_verified, auth_type, created_at, updated_at, deleted_at
from accounts
where email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            error!(email = %email, error = %e, "Database error finding account by email (including deleted)");
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
select id, email, password_hash, email_verified, auth_type, created_at, updated_at, deleted_at
from accounts
where id = $1
  and deleted_at is null
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

    pub async fn find_account_by_id_including_deleted(
        &self,
        account_id: AccountId,
    ) -> Result<Option<Account>, IamError> {
        let rec = sqlx::query_as::<_, Account>(
            r#"
select id, email, password_hash, email_verified, auth_type, created_at, updated_at, deleted_at
from accounts
where id = $1
            "#,
        )
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            error!(account_id = %account_id, error = %e, "Database error finding account by id (including deleted)");
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
        root_token: Option<&str>,
        usage: i64,
    ) -> Result<Token, IamError> {
        let rec = sqlx::query_as::<_, Token>(
            r#"
insert into tokens (id, account_id, token, token_type, expires_at, created_at, revoked_at, root_token, usage)
values ($1, $2, $3, $4, $5, $6, null, $7, $8)
returning id, account_id, token, token_type, expires_at, created_at, revoked_at, root_token, usage
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(account_id)
        .bind(token)
        .bind(token_type)
        .bind(expires_at)
        .bind(now)
        .bind(root_token)
        .bind(usage)
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
select id, account_id, token, token_type, expires_at, created_at, revoked_at, root_token, usage
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
        now: DateTime<Utc>,
    ) -> Result<(), IamError> {
        // Soft delete: set deleted_at instead of actually deleting
        sqlx::query(
            r#"
update accounts
set deleted_at = $2,
    updated_at = $2
where id = $1
  and deleted_at is null
            "#,
        )
        .bind(account_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(account_id = %account_id, error = %e, "Database error soft-deleting account");
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

    pub async fn revoke_tokens_by_root_token(
        &self,
        root_token: &str,
        now: DateTime<Utc>,
    ) -> Result<(), IamError> {
        sqlx::query(
            r#"
update tokens
set revoked_at = $2
where root_token = $1
  and revoked_at is null
            "#,
        )
        .bind(root_token)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(root_token = %root_token, error = %e, "Database error revoking tokens by root_token");
            IamError::from(e)
        })?;

        Ok(())
    }

    pub async fn increment_token_usage(
        &self,
        token: &str,
        token_type: TokenType,
    ) -> Result<Token, IamError> {
        // First increment the usage counter
        sqlx::query(
            r#"
update tokens
set usage = usage + 1
where token = $1
  and token_type = $2
  and revoked_at is null
            "#,
        )
        .bind(token)
        .bind(token_type)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(token_type = ?token_type, error = %e, "Database error incrementing token usage");
            IamError::from(e)
        })?;

        // Then fetch the updated token
        let rec = sqlx::query_as::<_, Token>(
            r#"
select id, account_id, token, token_type, expires_at, created_at, revoked_at, root_token, usage
from tokens
where token = $1
  and token_type = $2
  and revoked_at is null
            "#,
        )
        .bind(token)
        .bind(token_type)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            error!(token_type = ?token_type, error = %e, "Database error fetching token after usage increment");
            IamError::from(e)
        })?;

        match rec {
            Some(row) => Ok(row),
            None => {
                warn!(token_type = ?token_type, "Token not found after usage increment");
                Err(IamError::TokenNotFound)
            }
        }
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

    /// Run database migrations
    /// 
    /// This method runs SQLx migrations from the `migrations/` directory.
    /// It uses PostgreSQL advisory locks to ensure only one instance runs migrations at a time.
    /// 
    /// # Concurrency
    /// Multiple instances can call this method simultaneously. The first instance
    /// will acquire a lock and run migrations. Other instances will wait for the
    /// lock (up to 30 seconds), then verify migrations are up to date.
    /// 
    /// # Errors
    /// Returns `IamError::Db` if there's a database error during migration execution.
    /// Returns `IamError::LockTimeout` if the lock cannot be acquired within the timeout.
    pub async fn migrate(&self) -> Result<(), IamError> {
        info!("Running database migrations");
        
        // Create a LeaseLock instance using the same pool
        let lock = LeaseLock::new(self.pool.clone());
        
        // Use a fixed lock key for migrations
        let lock_key = "iam_migrations";
        
        // Try to acquire lock and run migrations
        // If lock acquisition fails (timeout), verify migrations are up to date
        match with_lock(&lock, lock_key, 30, || async {
            self.migrate_internal().await
        })
        .await
        {
            Ok(()) => Ok(()),
            Err(IamError::LockTimeout) => {
                warn!("Failed to acquire migration lock within timeout, verifying migrations are up to date");
                // Another instance might have run migrations, verify and return success if up to date
                self.verify_migrations_up_to_date().await
            }
            Err(e) => Err(e),
        }
    }

    /// Internal method that actually runs migrations
    /// 
    /// The `sqlx::migrate!()` macro embeds migrations at compile time.
    /// The path "src/migrations" is resolved relative to the crate root (CARGO_MANIFEST_DIR)
    /// when the library is compiled. When this library is used as a dependency in another
    /// project, the migrations are already embedded in the compiled library, so the path
    /// works correctly without any additional configuration.
    async fn migrate_internal(&self) -> Result<(), IamError> {
        debug!("Executing migrations");
        
        // Retry migration execution in case of transient errors
        retry(|| async {
            // Path is resolved relative to crate root at compile time
            // Migrations are embedded in the compiled library
            sqlx::migrate!("src/migrations")
                .run(&self.pool)
                .await
                .map_err(|e| {
                    error!(error = %e, "Failed to run migrations");
                    // Convert MigrateError to sqlx::Error
                    IamError::Db(sqlx::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Migration error: {}", e)
                    )))
                })
        })
        .await?;

        info!("Database migrations completed successfully");
        Ok(())
    }

    /// Verify that migrations are up to date
    async fn verify_migrations_up_to_date(&self) -> Result<(), IamError> {
        debug!("Verifying migrations are up to date");
        
        // Check if the _sqlx_migrations table exists (created by SQLx)
        let migrations_table_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = '_sqlx_migrations'
            )"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to verify migrations table");
            IamError::Db(e)
        })?;

        if !migrations_table_exists {
            return Err(IamError::Db(sqlx::Error::RowNotFound));
        }

        // Verify all required tables exist
        self.verify_schema_exists().await
    }

    /// Verify that the schema already exists
    /// Returns Ok(()) if all required tables and types exist
    pub async fn verify_schema_exists(&self) -> Result<(), IamError> {
        debug!("Verifying schema existence");
        
        // Check if token_type enum exists
        let token_type_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM pg_type 
                WHERE typname = 'token_type' 
                AND typtype = 'e'
            )"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to verify token_type enum");
            IamError::Db(e)
        })?;

        if !token_type_exists {
            return Err(IamError::Db(sqlx::Error::RowNotFound));
        }

        // Check if auth_type enum exists
        let auth_type_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM pg_type 
                WHERE typname = 'auth_type' 
                AND typtype = 'e'
            )"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to verify auth_type enum");
            IamError::Db(e)
        })?;

        if !auth_type_exists {
            return Err(IamError::Db(sqlx::Error::RowNotFound));
        }

        // Check if all tables exist
        let tables_exist: bool = sqlx::query_scalar(
            "SELECT (
                SELECT COUNT(*) FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name IN ('accounts', 'tokens', 'email_verifications')
            ) = 3"
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to verify tables");
            IamError::Db(e)
        })?;

        if !tables_exist {
            return Err(IamError::Db(sqlx::Error::RowNotFound));
        }

        debug!("Schema verification successful - all objects exist");
        Ok(())
    }

    /// Cleanup expired and consumed objects from the database
    /// 
    /// Deletes:
    /// - Expired tokens (where `expires_at < now`)
    /// - Revoked tokens (where `revoked_at is not null`)
    /// - Expired email verifications (where `expires_at < now`)
    /// - Consumed email verifications (where `consumed_at is not null`)
    /// - Soft-deleted accounts (where `deleted_at < now - retention_period`)
    /// 
    /// # Parameters
    /// - `now`: Current timestamp
    /// - `account_retention_days`: Number of days to retain soft-deleted accounts before permanent deletion (default: 30)
    /// 
    /// # Returns
    /// A tuple containing the number of deleted tokens, email verifications, and accounts
    /// 
    /// # Errors
    /// Returns `IamError::Db` if there's a database error during cleanup
    pub async fn cleanup_expired_objects(
        &self,
        now: DateTime<Utc>,
        account_retention_days: i64,
    ) -> Result<(u64, u64, u64), IamError> {
        debug!("Starting cleanup of expired and consumed objects");
        
        // Delete expired and revoked tokens
        let deleted_tokens = retry(|| async {
            sqlx::query(
                r#"
                delete from tokens
                where expires_at < $1
                   or revoked_at is not null
                "#,
            )
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to delete expired/revoked tokens");
                IamError::Db(e)
            })
            .map(|result| result.rows_affected())
        })
        .await?;

        // Delete expired and consumed email verifications
        let deleted_verifications = retry(|| async {
            sqlx::query(
                r#"
                delete from email_verifications
                where expires_at < $1
                   or consumed_at is not null
                "#,
            )
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to delete expired/consumed email verifications");
                IamError::Db(e)
            })
            .map(|result| result.rows_affected())
        })
        .await?;

        // Delete accounts that have been soft-deleted for longer than retention period
        let retention_threshold = now - chrono::Duration::days(account_retention_days);
        let deleted_accounts = retry(|| async {
            sqlx::query(
                r#"
                delete from accounts
                where deleted_at is not null
                  and deleted_at <= $1
                "#,
            )
            .bind(retention_threshold)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to delete old soft-deleted accounts");
                IamError::Db(e)
            })
            .map(|result| result.rows_affected())
        })
        .await?;

        info!(
            deleted_tokens = deleted_tokens,
            deleted_verifications = deleted_verifications,
            deleted_accounts = deleted_accounts,
            "Cleanup completed"
        );

        Ok((deleted_tokens, deleted_verifications, deleted_accounts))
    }
}

