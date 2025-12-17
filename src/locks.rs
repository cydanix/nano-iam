use sqlx::{Pool, Postgres};
use tracing::{error, warn, debug};

use crate::errors::IamError;

/// Lease lock manager using PostgreSQL advisory locks
/// 
/// # Purpose
/// 
/// Locks are required for distributed PostgreSQL deployments to prevent race conditions:
/// 
/// 1. **Token Refresh** - Prevents double-spending the same refresh token
///    - Without lock: Two concurrent requests could both use the same refresh token
///    - With lock: Only one request can refresh a token at a time
/// 
/// 2. **Email Verification** - Prevents using the same verification code twice
///    - Without lock: Two concurrent requests could both verify with the same code
///    - With lock: Only one request can consume a verification code
/// 
/// 3. **Password Reset** - Prevents using the same reset code twice
///    - Without lock: Two concurrent requests could both reset with the same code
///    - With lock: Only one request can consume a reset code
/// 
/// 4. **Google OAuth Account Creation** - Prevents duplicate account creation
///    - Without lock: Two concurrent OAuth logins could try to create the same account
///    - With lock: Only one request creates the account, the other reuses it
/// 
/// 5. **Change Password** - Prevents password change race conditions
///    - Without lock: Two concurrent password changes could cause inconsistent state
///    - With lock: Only one password change can happen at a time per account
/// 
/// 6. **Cleanup Expired Objects** - Prevents multiple cleanup jobs running simultaneously
///    - Without lock: Multiple cleanup jobs waste resources
///    - With lock: Only one cleanup job runs at a time
/// 
/// # Master-Slave Setup
/// 
/// When using a master-slave PostgreSQL setup:
/// - **Always use the master database connection for locks**
/// - Read replicas cannot acquire advisory locks
/// - All lock operations must go through the master
/// - Use the same database pool for both `Repo` and `LeaseLock`

pub type PgPool = Pool<Postgres>;

/// Lease lock manager using PostgreSQL advisory locks
/// 
/// Provides distributed locking for critical sections in IAM operations.
/// Uses PostgreSQL advisory locks which work across all database connections
/// and are automatically released when the connection closes or transaction ends.
pub struct LeaseLock {
    pool: PgPool,
}

impl LeaseLock {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Acquire a lease lock for a given key
    /// 
    /// # Parameters
    /// - `key`: A unique identifier for the lock (e.g., token value, account_id + code)
    /// - `timeout_secs`: Maximum time to wait for the lock (0 = don't wait, fail immediately)
    /// 
    /// # Returns
    /// - `Ok(true)` if lock was acquired
    /// - `Ok(false)` if lock could not be acquired (timeout or already held)
    /// - `Err` if there was a database error
    /// 
    /// # Notes
    /// - Uses PostgreSQL advisory locks (pg_advisory_lock)
    /// - Locks are automatically released when the connection/transaction ends
    /// - For distributed systems, ensure all instances connect to the same master database
    pub async fn try_acquire(
        &self,
        key: &str,
        timeout_secs: u64,
    ) -> Result<bool, IamError> {
        // Hash the key to a 64-bit integer for advisory lock
        let lock_id = self.hash_key_to_i64(key);
        
        debug!(key = %key, lock_id = lock_id, timeout_secs = timeout_secs, "Attempting to acquire lease lock");

        if timeout_secs == 0 {
            // Try to acquire lock without waiting
            let result = sqlx::query_scalar::<_, bool>(
                "select pg_try_advisory_lock($1)",
            )
            .bind(lock_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                error!(key = %key, lock_id = lock_id, error = %e, "Failed to acquire advisory lock");
                IamError::Db(e)
            })?;

            if result {
                debug!(key = %key, lock_id = lock_id, "Lease lock acquired");
            } else {
                debug!(key = %key, lock_id = lock_id, "Lease lock not available");
            }
            Ok(result)
        } else {
            // Acquire lock with timeout using retry loop
            // pg_try_advisory_lock_timeout may not be available in all PostgreSQL versions
            // So we use pg_try_advisory_lock in a retry loop with exponential backoff
            use tokio::time::{sleep, Duration, Instant};
            
            let start = Instant::now();
            let timeout = Duration::from_secs(timeout_secs);
            let mut retry_delay = Duration::from_millis(50);
            let max_retry_delay = Duration::from_millis(500);
            
            loop {
                let acquired = sqlx::query_scalar::<_, bool>(
                    "select pg_try_advisory_lock($1)",
                )
                .bind(lock_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| {
                    error!(key = %key, lock_id = lock_id, error = %e, "Failed to try acquire advisory lock");
                    IamError::Db(e)
                })?;

                if acquired {
                    debug!(key = %key, lock_id = lock_id, "Lease lock acquired with timeout");
                    return Ok(true);
                }

                // Check if we've exceeded the timeout
                if start.elapsed() >= timeout {
                    debug!(key = %key, lock_id = lock_id, "Failed to acquire lock within timeout");
                    return Ok(false);
                }

                // Wait before retrying
                sleep(retry_delay).await;
                retry_delay = (retry_delay * 2).min(max_retry_delay);
            }
        }
    }

    /// Release a lease lock
    /// 
    /// # Notes
    /// - Locks are automatically released when connection/transaction ends
    /// - This is mainly for explicit cleanup if needed
    pub async fn release(&self, key: &str) -> Result<(), IamError> {
        let lock_id = self.hash_key_to_i64(key);
        
        sqlx::query("select pg_advisory_unlock($1)")
            .bind(lock_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(key = %key, lock_id = lock_id, error = %e, "Failed to release advisory lock");
                IamError::Db(e)
            })?;

        debug!(key = %key, lock_id = lock_id, "Lease lock released");
        Ok(())
    }

    /// Hash a string key to a 64-bit integer for PostgreSQL advisory locks
    /// 
    /// Uses a simple hash function. For better distribution, consider using
    /// a cryptographic hash, but for IAM use cases, this should be sufficient.
    fn hash_key_to_i64(&self, key: &str) -> i64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish();
        // Convert u64 to i64, handling sign bit
        hash as i64
    }
}

/// Helper to acquire and hold a lock for a critical section
/// 
/// Note: PostgreSQL advisory locks are automatically released when the
/// connection/transaction ends, so explicit release is optional but recommended.
pub async fn with_lock<F, Fut, T>(
    lock: &LeaseLock,
    key: &str,
    timeout_secs: u64,
    f: F,
) -> Result<T, IamError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, IamError>>,
{
    let acquired = lock.try_acquire(key, timeout_secs).await?;
    
    if !acquired {
        warn!(key = %key, "Failed to acquire lock");
        return Err(IamError::LockTimeout);
    }

    // Execute the critical section
    let result = f().await;

    // Release the lock
    if let Err(e) = lock.release(key).await {
        warn!(key = %key, error = %e, "Failed to release lock");
    }

    result
}

