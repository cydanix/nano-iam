use std::sync::Arc;

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use tracing::{error, warn, info, debug};

use crate::email::EmailSender;
use crate::errors::IamError;
use crate::google_oauth::verify_google_id_token;
use crate::locks::{LeaseLock, with_lock};
use crate::models::{Account, AccountId, AuthType, TokenPair, TokenType};
use crate::repo::Repo;
use crate::retry::retry;
use crate::tokens::generate_token_pair;

#[derive(Debug, Clone)]
pub struct TokenConfig {
    pub access_ttl: Duration,
    pub refresh_ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct EmailVerificationConfig {
    pub code_ttl: Duration,
    pub code_length: usize,
}

#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
    pub block_common_passwords: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            block_common_passwords: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub token: TokenConfig,
    pub email_verification: EmailVerificationConfig,
    pub password_policy: PasswordPolicy,
    pub service_name: Option<String>,
}

pub struct AuthService {
    repo: Repo,
    email_sender: Arc<dyn EmailSender>,
    cfg: AuthConfig,
    lock: Option<LeaseLock>,
}

#[derive(Debug, Clone)]
pub struct LoginResult {
    pub account: Account,
    pub tokens: TokenPair,
}

#[derive(Debug, Clone)]
pub struct RefreshResult {
    pub account: Account,
    pub tokens: TokenPair,
}

impl AuthService {
    pub fn new(repo: Repo, email_sender: Arc<dyn EmailSender>, cfg: AuthConfig) -> Self {
        Self {
            repo,
            email_sender,
            cfg,
            lock: None,
        }
    }

    /// Create AuthService with lease locking enabled
    /// 
    /// # Parameters
    /// - `repo`: Repository with database connection
    /// - `email_sender`: Email sender implementation
    /// - `cfg`: Authentication configuration
    /// - `lock`: Lease lock manager (must use the same database pool as repo)
    /// 
    /// # Notes
    /// - Locks are only needed for distributed deployments
    /// - For single-instance deployments, you can use `new()` without locks
    /// - When using master-slave setup, ensure lock uses the master database connection
    pub fn with_locks(
        repo: Repo,
        email_sender: Arc<dyn EmailSender>,
        cfg: AuthConfig,
        lock: LeaseLock,
    ) -> Self {
        Self {
            repo,
            email_sender,
            cfg,
            lock: Some(lock),
        }
    }

    fn hash_password(&self, password: &str) -> Result<String, IamError> {
        let salt = SaltString::generate(&mut rand::thread_rng());
        let argon2 = Argon2::default();
        argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| {
                error!(error = %e, "Failed to hash password");
                IamError::Hash(e.to_string())
            })
            .map(|p| p.to_string())
    }

    fn verify_password(
        &self,
        password: &str,
        hash: &str,
    ) -> Result<bool, IamError> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| {
                error!(error = %e, "Failed to parse password hash");
                IamError::Hash(e.to_string())
            })?;
        let argon2 = Argon2::default();
        Ok(argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }

    fn validate_password_complexity(&self, password: &str) -> Result<(), IamError> {
        let policy = &self.cfg.password_policy;

        if password.len() < policy.min_length {
            return Err(IamError::WeakPassword(format!(
                "Password must be at least {} characters long",
                policy.min_length
            )));
        }

        let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| c.is_ascii_punctuation());

        let mut missing = Vec::new();
        if policy.require_uppercase && !has_uppercase {
            missing.push("uppercase letter");
        }
        if policy.require_lowercase && !has_lowercase {
            missing.push("lowercase letter");
        }
        if policy.require_digit && !has_digit {
            missing.push("digit");
        }
        if policy.require_special && !has_special {
            missing.push("special character");
        }

        if !missing.is_empty() {
            return Err(IamError::WeakPassword(format!(
                "Password must contain at least one: {}",
                missing.join(", ")
            )));
        }

        // Check against common weak passwords if enabled
        if policy.block_common_passwords {
            let weak_passwords = [
                "password", "password123", "12345678", "qwerty123", "abc12345",
                "welcome123", "admin123", "letmein", "monkey", "1234567890",
            ];
            let password_lower = password.to_lowercase();
            for weak in &weak_passwords {
                if password_lower.contains(weak) {
                    return Err(IamError::WeakPassword(
                        "Password is too common or easily guessable".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    pub async fn register(
        &self,
        email: &str,
        password: &str,
    ) -> Result<Account, IamError> {
        self.register_with_auth_type(email, password, AuthType::Email).await
    }

    pub async fn register_with_auth_type(
        &self,
        email: &str,
        password: &str,
        auth_type: AuthType,
    ) -> Result<Account, IamError> {
        info!(email = %email, auth_type = ?auth_type, "Registering new account");
        
        let now = self.now();
        let password_hash = match auth_type {
            AuthType::Email => {
                self.validate_password_complexity(password)?;
                self.hash_password(password)?
            }
            AuthType::Google => {
                // For Google OAuth, password is the ID token
                // We'll verify it and extract email, but don't store password hash
                // Use a placeholder hash since the field is required
                String::new()
            }
        };

        // Retry database operations that may fail due to transient errors
        let account = retry(|| async {
            self.repo
                .create_account(email, &password_hash, auth_type, now)
                .await
                .map_err(|e| {
                    error!(email = %email, error = %e, "Failed to create account");
                    e
                })
        })
        .await?;

        // Only send verification email for email-based accounts
        if auth_type == AuthType::Email {
            let code =
                self.generate_verification_code(self.cfg.email_verification.code_length);
            let expires_at = now + self.cfg.email_verification.code_ttl;

            retry(|| async {
                self.repo
                    .create_email_verification(account.id, &code, expires_at, now)
                    .await
                    .map_err(|e| {
                        error!(account_id = %account.id, error = %e, "Failed to create email verification");
                        e
                    })
            })
            .await?;

            self.email_sender
                .send_verification_email(&account.email, &code, self.cfg.service_name.as_deref())
                .await
                .map_err(|e| {
                    error!(email = %account.email, error = %e, "Failed to send verification email");
                    e
                })?;
        }

        info!(account_id = %account.id, email = %account.email, "Account registered successfully");
        Ok(account)
    }

    fn generate_verification_code(&self, len: usize) -> String {
        let mut rng = rand::thread_rng();
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        bytes
            .into_iter()
            .map(|b| ((b % 10) + b'0') as char)
            .collect()
    }

    pub async fn verify_email(
        &self,
        account_id: AccountId,
        code: &str,
    ) -> Result<(), IamError> {
        debug!(account_id = %account_id, "Verifying email");
        
        // Critical section: Prevent using the same verification code twice
        // Lock key: "verify_email:{account_id}:{code}"
        let lock_key = format!("verify_email:{}:{}", account_id, code);
        
        if let Some(lock) = &self.lock {
            with_lock(lock, &lock_key, 5, || async {
                self.verify_email_internal(account_id, code).await
            }).await
        } else {
            self.verify_email_internal(account_id, code).await
        }
    }

    async fn verify_email_internal(
        &self,
        account_id: AccountId,
        code: &str,
    ) -> Result<(), IamError> {
        let now = self.now();

        // Retry database operations that may fail due to transient errors
        retry(|| async {
            self.repo
                .consume_email_verification(account_id, code, now)
                .await
                .map_err(|e| {
                    warn!(account_id = %account_id, error = %e, "Email verification failed");
                    e
                })
        })
        .await?;

        retry(|| async {
            self.repo
                .mark_email_verified(account_id, now)
                .await
                .map_err(|e| {
                    error!(account_id = %account_id, error = %e, "Failed to mark email as verified");
                    e
                })
        })
        .await?;

        info!(account_id = %account_id, "Email verified successfully");
        Ok(())
    }

    pub async fn login(
        &self,
        email: &str,
        password: &str,
    ) -> Result<LoginResult, IamError> {
        self.login_with_auth_type(email, password, AuthType::Email).await
    }

    pub async fn login_with_auth_type(
        &self,
        email_or_token: &str,
        password_or_id_token: &str,
        auth_type: AuthType,
    ) -> Result<LoginResult, IamError> {
        debug!(auth_type = ?auth_type, "Attempting login");
        
        let email = match auth_type {
            AuthType::Google => {
                // For Google OAuth, password_or_id_token is the Google ID token
                verify_google_id_token(password_or_id_token).await?
            }
            AuthType::Email => {
                email_or_token.to_string()
            }
        };

        let account = self
            .repo
            .find_account_by_email(&email)
            .await
            .map_err(|e| {
                error!(email = %email, error = %e, "Database error during login");
                e
            })?;

        // If account doesn't exist and it's Google OAuth, create it automatically
        let account = match account {
            Some(acc) => acc,
            None => {
                if auth_type == AuthType::Google {
                    // Auto-create account for Google OAuth (email is already verified by Google)
                    info!(email = %email, "Auto-creating account for Google OAuth");
                    let now = self.now();
                    retry(|| async {
                        self.repo
                            .create_account(&email, "", AuthType::Google, now)
                            .await
                            .map_err(|e| {
                                error!(email = %email, error = %e, "Failed to create Google OAuth account");
                                e
                            })
                    })
                    .await?
                } else {
                    warn!(email = %email, "Login failed: account not found");
                    return Err(IamError::InvalidCredentials);
                }
            }
        };

        // Verify auth type matches
        if account.auth_type != auth_type {
            warn!(
                account_id = %account.id,
                email = %email,
                account_auth_type = ?account.auth_type,
                requested_auth_type = ?auth_type,
                "Login failed: account has different authentication type"
            );
            return Err(IamError::AuthTypeMismatch);
        }

        if !account.email_verified {
            warn!(account_id = %account.id, email = %email, "Login failed: email not verified");
            return Err(IamError::EmailNotVerified);
        }

        // Verify password for email-based accounts
        if auth_type == AuthType::Email {
            if !self.verify_password(password_or_id_token, &account.password_hash)? {
                warn!(account_id = %account.id, email = %email, "Login failed: invalid password");
                return Err(IamError::InvalidCredentials);
            }
        }

        let tokens = self.issue_tokens_for_account(account.id).await
            .map_err(|e| {
                error!(account_id = %account.id, error = %e, "Failed to issue tokens");
                e
            })?;

        info!(account_id = %account.id, email = %email, "Login successful");
        Ok(LoginResult { account, tokens })
    }

    async fn issue_tokens_for_account(
        &self,
        account_id: AccountId,
    ) -> Result<TokenPair, IamError> {
        self.issue_tokens_for_account_with_root_token(account_id, None).await
    }

    async fn issue_tokens_for_account_with_root_token(
        &self,
        account_id: AccountId,
        root_token: Option<&str>,
    ) -> Result<TokenPair, IamError> {
        debug!(account_id = %account_id, "Issuing tokens");
        let now = self.now();
        let pair = generate_token_pair(
            self.cfg.token.access_ttl,
            self.cfg.token.refresh_ttl,
        );

        // Determine root_token: use provided one, or use refresh token value as root
        let refresh_token_value = pair.refresh_token.as_str();
        let root_token = root_token.unwrap_or(refresh_token_value);

        // Retry database operations that may fail due to transient errors
        // Insert refresh token first with root_token
        retry(|| async {
            self.repo
                .insert_token(
                    account_id,
                    refresh_token_value,
                    TokenType::Refresh,
                    pair.refresh_token_expires_at,
                    now,
                    Some(root_token),
                    0, // Initial usage is 0
                )
                .await
                .map_err(|e| {
                    error!(account_id = %account_id, error = %e, "Failed to insert refresh token");
                    e
                })
        })
        .await?;

        // Insert access token with the same root_token
        retry(|| async {
            self.repo
                .insert_token(
                    account_id,
                    pair.access_token.as_str(),
                    TokenType::Access,
                    pair.access_token_expires_at,
                    now,
                    Some(root_token),
                    0, // Access tokens don't track usage
                )
                .await
                .map_err(|e| {
                    error!(account_id = %account_id, error = %e, "Failed to insert access token");
                    e
                })
        })
        .await?;

        Ok(pair)
    }

    pub async fn refresh(
        &self,
        refresh_token: &str,
    ) -> Result<RefreshResult, IamError> {
        debug!("Refreshing tokens");
        
        // Critical section: Prevent double-spending the same refresh token
        // Lock key: "refresh_token:{token_value}"
        let lock_key = format!("refresh_token:{}", refresh_token);
        
        if let Some(lock) = &self.lock {
            with_lock(lock, &lock_key, 5, || async {
                self.refresh_internal(refresh_token).await
            }).await
        } else {
            // No locks configured, proceed without locking
            // Note: In distributed setups, this could allow race conditions
            self.refresh_internal(refresh_token).await
        }
    }

    async fn refresh_internal(
        &self,
        refresh_token: &str,
    ) -> Result<RefreshResult, IamError> {
        let now = self.now();

        // Retry read operations that may fail due to transient errors
        let stored = retry(|| async {
            self.repo
                .find_valid_token(refresh_token, TokenType::Refresh, now)
                .await
                .map_err(|e| {
                    warn!(error = %e, "Token refresh failed: invalid or expired token");
                    e
                })
        })
        .await?;

        // Increment usage counter and check for double usage
        let updated_token = retry(|| async {
            self.repo
                .increment_token_usage(refresh_token, TokenType::Refresh)
                .await
                .map_err(|e| {
                    error!(error = %e, "Failed to increment token usage");
                    e
                })
        })
        .await?;

        // Check for double usage (token reused in another location - compromised)
        if updated_token.usage > 1 {
            error!(
                account_id = %updated_token.account_id,
                root_token = ?updated_token.root_token,
                usage = updated_token.usage,
                "Refresh token double usage detected - token may be compromised"
            );

            // Revoke entire token chain if root_token exists
            if let Some(ref root_token) = updated_token.root_token {
                retry(|| async {
                    self.repo
                        .revoke_tokens_by_root_token(root_token, now)
                        .await
                        .map_err(|e| {
                            error!(root_token = %root_token, error = %e, "Failed to revoke token chain");
                            e
                        })
                })
                .await?;
            } else {
                // Fallback: revoke just this token if no root_token
                retry(|| async {
                    self.repo
                        .revoke_token(refresh_token, TokenType::Refresh, now)
                        .await
                        .map_err(|e| {
                            error!(error = %e, "Failed to revoke compromised refresh token");
                            e
                        })
                })
                .await?;
            }

            return Err(IamError::TokenReuseDetected);
        }

        // Revoke the used refresh token (single-use token)
        retry(|| async {
            self.repo
                .revoke_token(refresh_token, TokenType::Refresh, now)
                .await
                .map_err(|e| {
                    error!(error = %e, "Failed to revoke refresh token");
                    e
                })
        })
        .await?;

        let account = self
            .repo
            .find_account_by_id(stored.account_id)
            .await
            .map_err(|e| {
                error!(account_id = %stored.account_id, error = %e, "Database error finding account");
                e
            })?
            .ok_or_else(|| {
                error!(account_id = %stored.account_id, "Account not found during token refresh");
                IamError::AccountNotFound
            })?;

        // Create new token pair with the same root_token
        let tokens = self.issue_tokens_for_account_with_root_token(account.id, updated_token.root_token.as_deref()).await
            .map_err(|e| {
                error!(account_id = %account.id, error = %e, "Failed to issue new tokens");
                e
            })?;

        info!(account_id = %account.id, "Tokens refreshed successfully");
        Ok(RefreshResult { account, tokens })
    }

    pub async fn authenticate_access_token(
        &self,
        access_token: &str,
    ) -> Result<Account, IamError> {
        debug!("Authenticating access token");
        let now = self.now();

        let stored = self
            .repo
            .find_valid_token(access_token, TokenType::Access, now)
            .await
            .map_err(|e| {
                warn!(error = %e, "Access token authentication failed");
                e
            })?;

        let account = self
            .repo
            .find_account_by_id_including_deleted(stored.account_id)
            .await
            .map_err(|e| {
                error!(account_id = %stored.account_id, error = %e, "Database error finding account");
                e
            })?
            .ok_or_else(|| {
                error!(account_id = %stored.account_id, "Account not found during token authentication");
                IamError::AccountNotFound
            })?;

        debug!(account_id = %account.id, "Access token authenticated successfully");
        Ok(account)
    }

    pub async fn delete_account(
        &self,
        account_id: AccountId,
        password: &str,
    ) -> Result<(), IamError> {
        info!(account_id = %account_id, "Deleting account");
        
        let account = self
            .repo
            .find_account_by_id(account_id)
            .await
            .map_err(|e| {
                error!(account_id = %account_id, error = %e, "Database error finding account");
                e
            })?
            .ok_or_else(|| {
                warn!(account_id = %account_id, "Account not found for deletion");
                IamError::AccountNotFound
            })?;

        if !self.verify_password(password, &account.password_hash)? {
            warn!(account_id = %account_id, "Account deletion failed: invalid password");
            return Err(IamError::InvalidCredentials);
        }

        let now = self.now();
        // Retry database operations that may fail due to transient errors
        retry(|| async {
            self.repo
                .delete_account(account_id, now)
                .await
                .map_err(|e| {
                    error!(account_id = %account_id, error = %e, "Failed to soft-delete account");
                    e
                })
        })
        .await?;

        info!(account_id = %account_id, "Account deleted successfully");
        Ok(())
    }

    pub async fn logout(
        &self,
        access_token: &str,
    ) -> Result<(), IamError> {
        debug!("Logging out");
        let now = self.now();

        // Retry database operations that may fail due to transient errors
        retry(|| async {
            self.repo
                .revoke_token(access_token, TokenType::Access, now)
                .await
                .map_err(|e| {
                    warn!(error = %e, "Failed to revoke access token during logout");
                    e
                })
        })
        .await?;

        info!("Logout successful");
        Ok(())
    }

    pub async fn logout_all(
        &self,
        account_id: AccountId,
        password: &str,
    ) -> Result<(), IamError> {
        info!(account_id = %account_id, "Logging out all sessions");
        
        let account = self
            .repo
            .find_account_by_id(account_id)
            .await
            .map_err(|e| {
                error!(account_id = %account_id, error = %e, "Database error finding account");
                e
            })?
            .ok_or_else(|| {
                warn!(account_id = %account_id, "Account not found for logout");
                IamError::AccountNotFound
            })?;

        if !self.verify_password(password, &account.password_hash)? {
            warn!(account_id = %account_id, "Logout all failed: invalid password");
            return Err(IamError::InvalidCredentials);
        }

        let now = self.now();
        // Retry database operations that may fail due to transient errors
        retry(|| async {
            self.repo
                .revoke_all_tokens(account_id, now)
                .await
                .map_err(|e| {
                    error!(account_id = %account_id, error = %e, "Failed to revoke all tokens");
                    e
                })
        })
        .await?;

        info!(account_id = %account_id, "All sessions logged out successfully");
        Ok(())
    }

    pub async fn change_password(
        &self,
        account_id: AccountId,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), IamError> {
        info!(account_id = %account_id, "Changing password");
        
        let account = self
            .repo
            .find_account_by_id(account_id)
            .await
            .map_err(|e| {
                error!(account_id = %account_id, error = %e, "Database error finding account");
                e
            })?
            .ok_or_else(|| {
                warn!(account_id = %account_id, "Account not found for password change");
                IamError::AccountNotFound
            })?;

        if !self.verify_password(old_password, &account.password_hash)? {
            warn!(account_id = %account_id, "Password change failed: invalid old password");
            return Err(IamError::InvalidCredentials);
        }

        self.validate_password_complexity(new_password)?;

        let now = self.now();
        let new_password_hash = self.hash_password(new_password)?;

        // Retry database operations that may fail due to transient errors
        retry(|| async {
            self.repo
                .update_password_hash(account_id, &new_password_hash, now)
                .await
                .map_err(|e| {
                    error!(account_id = %account_id, error = %e, "Failed to update password");
                    e
                })
        })
        .await?;

        // Revoke all existing tokens after password change for security
        retry(|| async {
            self.repo
                .revoke_all_tokens(account_id, now)
                .await
                .map_err(|e| {
                    error!(account_id = %account_id, error = %e, "Failed to revoke tokens after password change");
                    e
                })
        })
        .await?;

        info!(account_id = %account_id, "Password changed successfully");
        Ok(())
    }

    pub async fn request_password_reset(
        &self,
        email: &str,
    ) -> Result<(), IamError> {
        info!(email = %email, "Requesting password reset");
        
        let account = self
            .repo
            .find_account_by_email(email)
            .await
            .map_err(|e| {
                error!(email = %email, error = %e, "Database error finding account");
                e
            })?
            .ok_or_else(|| {
                // Don't reveal if email exists for security
                warn!(email = %email, "Password reset requested for non-existent email");
                IamError::AccountNotFound
            })?;

        let now = self.now();
        let code = self.generate_verification_code(self.cfg.email_verification.code_length);
        let expires_at = now + self.cfg.email_verification.code_ttl;

        // Invalidate any existing password reset codes
        // (We could add a method to delete old codes, but creating a new one works)
        
        // Retry database operations that may fail due to transient errors
        retry(|| async {
            self.repo
                .create_email_verification(account.id, &code, expires_at, now)
                .await
                .map_err(|e| {
                    error!(account_id = %account.id, error = %e, "Failed to create password reset code");
                    e
                })
        })
        .await?;

        self.email_sender
            .send_password_reset_email(&account.email, &code, self.cfg.service_name.as_deref())
            .await
            .map_err(|e| {
                error!(email = %account.email, error = %e, "Failed to send password reset email");
                e
            })?;

        info!(account_id = %account.id, email = %account.email, "Password reset code sent");
        Ok(())
    }

    pub async fn reset_password(
        &self,
        email: &str,
        code: &str,
        new_password: &str,
    ) -> Result<(), IamError> {
        info!(email = %email, "Resetting password");
        
        let account = self
            .repo
            .find_account_by_email(email)
            .await
            .map_err(|e| {
                error!(email = %email, error = %e, "Database error finding account");
                e
            })?
            .ok_or_else(|| {
                warn!(email = %email, "Account not found for password reset");
                IamError::AccountNotFound
            })?;

        // Critical section: Prevent using the same reset code twice
        // Lock key: "reset_password:{account_id}:{code}"
        let lock_key = format!("reset_password:{}:{}", account.id, code);
        
        if let Some(lock) = &self.lock {
            with_lock(lock, &lock_key, 5, || async {
                self.reset_password_internal(&account, code, new_password).await
            }).await
        } else {
            self.reset_password_internal(&account, code, new_password).await
        }
    }

    async fn reset_password_internal(
        &self,
        account: &Account,
        code: &str,
        new_password: &str,
    ) -> Result<(), IamError> {
        let now = self.now();
        // Retry database operations that may fail due to transient errors
        retry(|| async {
            self.repo
                .consume_email_verification(account.id, code, now)
                .await
                .map_err(|e| {
                    warn!(account_id = %account.id, error = %e, "Password reset code validation failed");
                    e
                })
        })
        .await?;

        self.validate_password_complexity(new_password)?;

        let new_password_hash = self.hash_password(new_password)?;
        retry(|| async {
            self.repo
                .update_password_hash(account.id, &new_password_hash, now)
                .await
                .map_err(|e| {
                    error!(account_id = %account.id, error = %e, "Failed to update password");
                    e
                })
        })
        .await?;

        // Revoke all existing tokens after password reset for security
        retry(|| async {
            self.repo
                .revoke_all_tokens(account.id, now)
                .await
                .map_err(|e| {
                    error!(account_id = %account.id, error = %e, "Failed to revoke tokens after password reset");
                    e
                })
        })
        .await?;

        info!(account_id = %account.id, email = %account.email, "Password reset successfully");
        Ok(())
    }

    pub async fn resend_verification_email(
        &self,
        email: &str,
    ) -> Result<(), IamError> {
        info!(email = %email, "Resending verification email");
        
        let account = self
            .repo
            .find_account_by_email(email)
            .await
            .map_err(|e| {
                error!(email = %email, error = %e, "Database error finding account");
                e
            })?
            .ok_or_else(|| {
                warn!(email = %email, "Account not found for resending verification");
                IamError::AccountNotFound
            })?;

        if account.email_verified {
            warn!(account_id = %account.id, email = %email, "Email already verified");
            return Err(IamError::EmailAlreadyVerified);
        }

        let now = self.now();
        let code = self.generate_verification_code(self.cfg.email_verification.code_length);
        let expires_at = now + self.cfg.email_verification.code_ttl;

        // Retry database operations that may fail due to transient errors
        retry(|| async {
            self.repo
                .create_email_verification(account.id, &code, expires_at, now)
                .await
                .map_err(|e| {
                    error!(account_id = %account.id, error = %e, "Failed to create email verification");
                    e
                })
        })
        .await?;

        self.email_sender
            .send_verification_email(&account.email, &code, self.cfg.service_name.as_deref())
            .await
            .map_err(|e| {
                error!(email = %account.email, error = %e, "Failed to send verification email");
                e
            })?;

        info!(account_id = %account.id, email = %account.email, "Verification email resent");
        Ok(())
    }

    pub async fn check_email_available(
        &self,
        email: &str,
    ) -> Result<bool, IamError> {
        let account = self
            .repo
            .find_account_by_email_including_deleted(email)
            .await
            .map_err(|e| {
                error!(email = %email, error = %e, "Database error checking email availability");
                e
            })?;

        Ok(account.is_none())
    }

    pub async fn get_account(
        &self,
        account_id: AccountId,
    ) -> Result<Account, IamError> {
        let account = self
            .repo
            .find_account_by_id(account_id)
            .await
            .map_err(|e| {
                error!(account_id = %account_id, error = %e, "Database error finding account");
                e
            })?
            .ok_or_else(|| {
                warn!(account_id = %account_id, "Account not found");
                IamError::AccountNotFound
            })?;

        Ok(account)
    }

    /// Cleanup expired and consumed objects from the database
    /// 
    /// This method should be called periodically (e.g., via a cron job or scheduled task)
    /// to remove expired tokens, email verifications, and permanently delete accounts
    /// that have been soft-deleted for longer than the retention period.
    /// 
    /// Deletes:
    /// - Expired tokens (where `expires_at < now`)
    /// - Revoked tokens (where `revoked_at is not null`)
    /// - Expired email verifications (where `expires_at < now`)
    /// - Consumed email verifications (where `consumed_at is not null`)
    /// - Soft-deleted accounts (where `deleted_at < now - account_retention_days`)
    /// 
    /// # Parameters
    /// - `account_retention_days`: Number of days to retain soft-deleted accounts before permanent deletion (e.g., 30)
    /// 
    /// # Returns
    /// A tuple containing the number of deleted tokens, email verifications, and accounts
    /// 
    /// # Example
    /// ```rust,no_run
    /// use iam::AuthService;
    /// 
    /// # async fn example(auth: AuthService) -> Result<(), Box<dyn std::error::Error>> {
    /// // Cleanup with 30-day retention for soft-deleted accounts
    /// let (tokens, verifications, accounts) = auth.cleanup_expired_objects(30).await?;
    /// println!("Deleted {} tokens, {} verifications, and {} accounts", tokens, verifications, accounts);
    /// # Ok(())
    /// # }
    /// ```
    /// 
    /// # Errors
    /// Returns `IamError::Db` if there's a database error during cleanup
    pub async fn cleanup_expired_objects(&self, account_retention_days: i64) -> Result<(u64, u64, u64), IamError> {
        info!(account_retention_days = account_retention_days, "Starting cleanup of expired and consumed objects");
        let now = self.now();
        self.repo.cleanup_expired_objects(now, account_retention_days).await
    }
}


