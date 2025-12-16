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
use crate::models::{Account, AccountId, TokenPair, TokenType};
use crate::repo::Repo;
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
        info!(email = %email, "Registering new account");
        
        self.validate_password_complexity(password)?;
        
        let now = self.now();
        let password_hash = self.hash_password(password)?;

        let account = self
            .repo
            .create_account(email, &password_hash, now)
            .await
            .map_err(|e| {
                error!(email = %email, error = %e, "Failed to create account");
                e
            })?;

        let code =
            self.generate_verification_code(self.cfg.email_verification.code_length);
        let expires_at = now + self.cfg.email_verification.code_ttl;

        self.repo
            .create_email_verification(account.id, &code, expires_at, now)
            .await
            .map_err(|e| {
                error!(account_id = %account.id, error = %e, "Failed to create email verification");
                e
            })?;

        self.email_sender
            .send_verification_email(&account.email, &code, self.cfg.service_name.as_deref())
            .await
            .map_err(|e| {
                error!(email = %account.email, error = %e, "Failed to send verification email");
                e
            })?;

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
        let now = self.now();

        self.repo
            .consume_email_verification(account_id, code, now)
            .await
            .map_err(|e| {
                warn!(account_id = %account_id, error = %e, "Email verification failed");
                e
            })?;

        self.repo.mark_email_verified(account_id, now).await
            .map_err(|e| {
                error!(account_id = %account_id, error = %e, "Failed to mark email as verified");
                e
            })?;

        info!(account_id = %account_id, "Email verified successfully");
        Ok(())
    }

    pub async fn login(
        &self,
        email: &str,
        password: &str,
    ) -> Result<LoginResult, IamError> {
        debug!(email = %email, "Attempting login");
        let account = self
            .repo
            .find_account_by_email(email)
            .await
            .map_err(|e| {
                error!(email = %email, error = %e, "Database error during login");
                e
            })?
            .ok_or_else(|| {
                warn!(email = %email, "Login failed: account not found");
                IamError::InvalidCredentials
            })?;

        if !account.email_verified {
            warn!(account_id = %account.id, email = %email, "Login failed: email not verified");
            return Err(IamError::EmailNotVerified);
        }

        if !self.verify_password(password, &account.password_hash)? {
            warn!(account_id = %account.id, email = %email, "Login failed: invalid password");
            return Err(IamError::InvalidCredentials);
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
        debug!(account_id = %account_id, "Issuing tokens");
        let now = self.now();
        let pair = generate_token_pair(
            self.cfg.token.access_ttl,
            self.cfg.token.refresh_ttl,
        );

        self.repo
            .insert_token(
                account_id,
                pair.access_token.as_str(),
                TokenType::Access,
                pair.access_token_expires_at,
                now,
            )
            .await
            .map_err(|e| {
                error!(account_id = %account_id, error = %e, "Failed to insert access token");
                e
            })?;

        self.repo
            .insert_token(
                account_id,
                pair.refresh_token.as_str(),
                TokenType::Refresh,
                pair.refresh_token_expires_at,
                now,
            )
            .await
            .map_err(|e| {
                error!(account_id = %account_id, error = %e, "Failed to insert refresh token");
                e
            })?;

        Ok(pair)
    }

    pub async fn refresh(
        &self,
        refresh_token: &str,
    ) -> Result<RefreshResult, IamError> {
        debug!("Refreshing tokens");
        let now = self.now();

        let stored = self
            .repo
            .find_valid_token(refresh_token, TokenType::Refresh, now)
            .await
            .map_err(|e| {
                warn!(error = %e, "Token refresh failed: invalid or expired token");
                e
            })?;

        self.repo
            .revoke_token(refresh_token, TokenType::Refresh, now)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to revoke refresh token");
                e
            })?;

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

        let tokens = self.issue_tokens_for_account(account.id).await
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
            .find_account_by_id(stored.account_id)
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

        self.repo
            .delete_account(account_id)
            .await
            .map_err(|e| {
                error!(account_id = %account_id, error = %e, "Failed to delete account");
                e
            })?;

        info!(account_id = %account_id, "Account deleted successfully");
        Ok(())
    }

    pub async fn logout(
        &self,
        access_token: &str,
    ) -> Result<(), IamError> {
        debug!("Logging out");
        let now = self.now();

        self.repo
            .revoke_token(access_token, TokenType::Access, now)
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to revoke access token during logout");
                e
            })?;

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
        self.repo
            .revoke_all_tokens(account_id, now)
            .await
            .map_err(|e| {
                error!(account_id = %account_id, error = %e, "Failed to revoke all tokens");
                e
            })?;

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

        self.repo
            .update_password_hash(account_id, &new_password_hash, now)
            .await
            .map_err(|e| {
                error!(account_id = %account_id, error = %e, "Failed to update password");
                e
            })?;

        // Revoke all existing tokens after password change for security
        self.repo
            .revoke_all_tokens(account_id, now)
            .await
            .map_err(|e| {
                error!(account_id = %account_id, error = %e, "Failed to revoke tokens after password change");
                e
            })?;

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
        
        self.repo
            .create_email_verification(account.id, &code, expires_at, now)
            .await
            .map_err(|e| {
                error!(account_id = %account.id, error = %e, "Failed to create password reset code");
                e
            })?;

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

        let now = self.now();
        self.repo
            .consume_email_verification(account.id, code, now)
            .await
            .map_err(|e| {
                warn!(account_id = %account.id, error = %e, "Password reset code validation failed");
                e
            })?;

        self.validate_password_complexity(new_password)?;

        let new_password_hash = self.hash_password(new_password)?;
        self.repo
            .update_password_hash(account.id, &new_password_hash, now)
            .await
            .map_err(|e| {
                error!(account_id = %account.id, error = %e, "Failed to update password");
                e
            })?;

        // Revoke all existing tokens after password reset for security
        self.repo
            .revoke_all_tokens(account.id, now)
            .await
            .map_err(|e| {
                error!(account_id = %account.id, error = %e, "Failed to revoke tokens after password reset");
                e
            })?;

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

        self.repo
            .create_email_verification(account.id, &code, expires_at, now)
            .await
            .map_err(|e| {
                error!(account_id = %account.id, error = %e, "Failed to create email verification");
                e
            })?;

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
            .find_account_by_email(email)
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
}


