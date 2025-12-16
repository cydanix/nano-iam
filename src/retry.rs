use std::time::Duration;
use sqlx::Error as SqlxError;
use sqlx::postgres::PgDatabaseError;
use tracing::{warn, debug};
use tokio::time::sleep;

use crate::errors::IamError;

/// Check if a database error is retryable (transient)
/// 
/// Retryable errors include:
/// - Serialization failures (40001): Transaction isolation conflicts
/// - Deadlock detection (40P01): Deadlock detected
/// - Lock not available (55P03): Cannot acquire lock
/// - Connection errors: Temporary network issues
pub fn is_retryable_db_error(error: &SqlxError) -> bool {
    match error {
        SqlxError::Database(db_err) => {
            if let Some(pg_err) = db_err.try_downcast_ref::<PgDatabaseError>() {
                let code = pg_err.code();
                // PostgreSQL error codes that indicate transient failures
                matches!(
                    code.as_ref(),
                    "40001" |  // Serialization failure
                    "40P01" | // Deadlock detected
                    "55P03" | // Lock not available
                    "08006" | // Connection failure
                    "08003" | // Connection does not exist
                    "08000"   // Connection exception
                )
            } else {
                false
            }
        }
        SqlxError::PoolTimedOut | SqlxError::PoolClosed => true,
        _ => false,
    }
}

/// Check if an IAM error is retryable
pub fn is_retryable_error(error: &IamError) -> bool {
    match error {
        IamError::Db(db_err) => is_retryable_db_error(db_err),
        _ => false, // Business logic errors should not be retried
    }
}

/// Retry configuration
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (including initial attempt)
    pub max_attempts: u32,
    /// Initial delay before first retry (in milliseconds)
    pub initial_delay_ms: u64,
    /// Maximum delay between retries (in milliseconds)
    pub max_delay_ms: u64,
    /// Exponential backoff multiplier
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 50,
            max_delay_ms: 1000,
            backoff_multiplier: 2.0,
        }
    }
}

/// Retry an async operation with exponential backoff
/// 
/// # Parameters
/// - `operation`: The async operation to retry
/// - `config`: Retry configuration
/// 
/// # Returns
/// - `Ok(T)` if the operation succeeds (on any attempt)
/// - `Err(IamError)` if all retries are exhausted or a non-retryable error occurs
pub async fn retry_with_backoff<F, Fut, T>(
    mut operation: F,
    config: RetryConfig,
) -> Result<T, IamError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, IamError>>,
{
    let mut delay_ms = config.initial_delay_ms;
    let mut last_error = None;

    for attempt in 1..=config.max_attempts {
        match operation().await {
            Ok(result) => {
                if attempt > 1 {
                    debug!(
                        attempt = attempt,
                        total_attempts = config.max_attempts,
                        "Operation succeeded after retry"
                    );
                }
                return Ok(result);
            }
            Err(e) => {
                if !is_retryable_error(&e) {
                    // Non-retryable error (e.g., invalid credentials, not found)
                    debug!(
                        error = %e,
                        "Non-retryable error encountered, aborting retries"
                    );
                    return Err(e);
                }

                last_error = Some(e);

                if attempt < config.max_attempts {
                    warn!(
                        attempt = attempt,
                        max_attempts = config.max_attempts,
                        delay_ms = delay_ms,
                        "Retryable error encountered, retrying after delay"
                    );
                    sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms = (delay_ms as f64 * config.backoff_multiplier) as u64;
                    delay_ms = delay_ms.min(config.max_delay_ms);
                } else {
                    warn!(
                        attempt = attempt,
                        max_attempts = config.max_attempts,
                        "All retry attempts exhausted"
                    );
                }
            }
        }
    }

    Err(last_error.expect("Should have at least one error after retries"))
}

/// Retry an async operation with default configuration
pub async fn retry<F, Fut, T>(operation: F) -> Result<T, IamError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, IamError>>,
{
    retry_with_backoff(operation, RetryConfig::default()).await
}

