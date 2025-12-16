use std::sync::{Arc, Mutex, Once};

use chrono::Duration;
use iam::{
    AuthConfig,
    AuthService,
    EmailVerificationConfig,
    TokenConfig,
};
use iam::email::EmailSender;
use iam::locks::{LeaseLock, with_lock};
use iam::repo::Repo;
use async_trait::async_trait;
use sqlx::postgres::PgPoolOptions;
use sqlx::Pool;
use sqlx::Postgres;

type PgPool = Pool<Postgres>;

// Initialize tracing subscriber once for all tests
// This allows RUST_LOG environment variable to control log levels
// 
// Usage:
//   RUST_LOG=debug cargo test -- --nocapture
//   RUST_LOG=trace cargo test --test integration -- --nocapture
//   RUST_LOG=iam::service=debug cargo test -- --nocapture
static INIT_TRACING: Once = Once::new();

fn init_tracing() {
    INIT_TRACING.call_once(|| {
        // Initialize tracing subscriber that respects RUST_LOG environment variable
        // Write to stderr so logs are visible (use --nocapture to see them in test output)
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug"));
        
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_ansi(true)
            .init();
    });
}

struct TestEmailSender {
    last: Arc<Mutex<Option<(String, String)>>>,
}

impl TestEmailSender {
    fn new() -> (Self, Arc<Mutex<Option<(String, String)>>>) {
        let shared = Arc::new(Mutex::new(None));
        let sender = Self {
            last: Arc::clone(&shared),
        };
        (sender, shared)
    }
}

#[async_trait]
impl EmailSender for TestEmailSender {
    async fn send_verification_email(
        &self,
        to: &str,
        code: &str,
        _service_name: Option<&str>,
    ) -> Result<(), iam::IamError> {
        let mut guard = self
            .last
            .lock()
            .expect("poisoned TestEmailSender mutex");
        *guard = Some((to.to_string(), code.to_string()));
        Ok(())
    }

    async fn send_password_reset_email(
        &self,
        to: &str,
        code: &str,
        _service_name: Option<&str>,
    ) -> Result<(), iam::IamError> {
        let mut guard = self
            .last
            .lock()
            .expect("poisoned TestEmailSender mutex");
        *guard = Some((to.to_string(), code.to_string()));
        Ok(())
    }
}

async fn setup_db() -> Result<PgPool, Box<dyn std::error::Error>> {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))?;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    let repo = iam::Repo::new(pool.clone());
    
    // Use a lock to safely drop and recreate schema for test isolation
    // This prevents race conditions when tests run in parallel
    let lock = LeaseLock::new(pool.clone());
    let lock_key = "test_db_setup";
    
    with_lock(&lock, lock_key, 30, || async {
        // Drop existing tables for clean test isolation
        // This ensures each test starts with a fresh schema
        sqlx::query(
            r#"
            do $$
            begin
                drop table if exists email_verifications cascade;
                drop table if exists tokens cascade;
                drop table if exists accounts cascade;
                drop type if exists token_type cascade;
            end
            $$;
            "#,
        )
        .execute(&pool)
        .await
        .map_err(|e| {
            eprintln!("Failed to drop tables: {}", e);
            iam::IamError::Db(e)
        })?;

        // Create schema
        repo.create_schema().await?;
        
        Ok::<(), iam::IamError>(())
    })
    .await
    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    Ok(pool)
}

async fn setup_auth_service(
) -> Result<(AuthService, Arc<Mutex<Option<(String, String)>>>), Box<dyn std::error::Error>>
{
    let pool = setup_db().await?;
    let repo = Repo::new(pool);

    let (sender, shared) = TestEmailSender::new();
    let email_sender = Arc::new(sender);

    let cfg = AuthConfig {
        token: TokenConfig {
            access_ttl: Duration::minutes(15),
            refresh_ttl: Duration::days(30),
        },
        email_verification: EmailVerificationConfig {
            code_ttl: Duration::minutes(10),
            code_length: 6,
        },
        password_policy: Default::default(),
        service_name: None,
    };

    let service = AuthService::new(repo, email_sender, cfg);

    Ok((service, shared))
}

async fn setup_auth_service_with_ttls(
    access_ttl: Duration,
    refresh_ttl: Duration,
) -> Result<(AuthService, Arc<Mutex<Option<(String, String)>>>), Box<dyn std::error::Error>>
{
    let pool = setup_db().await?;
    let repo = Repo::new(pool);

    let (sender, shared) = TestEmailSender::new();
    let email_sender = Arc::new(sender);

    let cfg = AuthConfig {
        token: TokenConfig {
            access_ttl,
            refresh_ttl,
        },
        email_verification: EmailVerificationConfig {
            code_ttl: Duration::minutes(10),
            code_length: 6,
        },
        password_policy: Default::default(),
        service_name: None,
    };

    let service = AuthService::new(repo, email_sender, cfg);

    Ok((service, shared))
}

#[tokio::test]
async fn full_auth_flow_register_verify_login_refresh(
) -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "test@example.com";
    let password = "ComplexStr0ng!";

    let account = auth.register(email, password).await?;

    // Check that verification email was "sent"
    let (sent_to, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };

    assert_eq!(sent_to, email);
    assert_eq!(code.len(), 6);

    // Verify email with captured code
    auth.verify_email(account.id, &code).await?;

    // Login should now succeed and issue tokens
    let login_result = auth.login(email, password).await?;
    assert_eq!(login_result.account.id, account.id);
    assert!(login_result.tokens.access_token.as_str().len() > 0);
    assert!(login_result.tokens.refresh_token.as_str().len() > 0);

    // Authenticate with access token
    let authed_account = auth
        .authenticate_access_token(login_result.tokens.access_token.as_str())
        .await?;
    assert_eq!(authed_account.id, account.id);

    // Refresh tokens
    let refresh_result = auth
        .refresh(login_result.tokens.refresh_token.as_str())
        .await?;
    assert_eq!(refresh_result.account.id, account.id);
    assert_ne!(
        refresh_result.tokens.access_token.as_str(),
        login_result.tokens.access_token.as_str()
    );
    assert_ne!(
        refresh_result.tokens.refresh_token.as_str(),
        login_result.tokens.refresh_token.as_str()
    );

    Ok(())
}

#[tokio::test]
async fn test_expired_access_token_fails_authentication(
) -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    // Use very short TTL for access token
    let (auth, sent_codes) = setup_auth_service_with_ttls(
        Duration::seconds(1),
        Duration::days(30),
    ).await?;

    let email = "expired@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Login to get tokens
    let login_result = auth.login(email, password).await?;

    // Access token should work immediately
    let authed_account = auth
        .authenticate_access_token(login_result.tokens.access_token.as_str())
        .await?;
    assert_eq!(authed_account.id, account.id);

    // Wait for access token to expire
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Expired access token should fail
    let result = auth
        .authenticate_access_token(login_result.tokens.access_token.as_str())
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::TokenExpired => {}
        e => panic!("Expected TokenExpired, got {:?}", e),
    }

    Ok(())
}

#[tokio::test]
async fn test_expired_refresh_token_fails_refresh(
) -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    // Use very short TTL for refresh token
    let (auth, sent_codes) = setup_auth_service_with_ttls(
        Duration::minutes(15),
        Duration::seconds(1),
    ).await?;

    let email = "expired_refresh@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Login to get tokens
    let login_result = auth.login(email, password).await?;

    // Refresh token should work immediately
    let refresh_result = auth
        .refresh(login_result.tokens.refresh_token.as_str())
        .await?;
    assert_eq!(refresh_result.account.id, account.id);

    // Wait for refresh token to expire
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Expired refresh token should fail
    let result = auth
        .refresh(refresh_result.tokens.refresh_token.as_str())
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::TokenExpired => {}
        e => panic!("Expected TokenExpired, got {:?}", e),
    }

    Ok(())
}

#[tokio::test]
async fn test_refresh_token_revoked_after_use(
) -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "revoked@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Login to get tokens
    let login_result = auth.login(email, password).await?;
    let refresh_token = login_result.tokens.refresh_token.as_str().to_string();

    // Use refresh token once
    let refresh_result = auth.refresh(&refresh_token).await?;
    assert_eq!(refresh_result.account.id, account.id);

    // Try to use the same refresh token again - should fail
    let result = auth.refresh(&refresh_token).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::TokenExpired => {}
        e => panic!("Expected TokenExpired (token was revoked), got {:?}", e),
    }

    // New refresh token should work
    let second_refresh = auth
        .refresh(refresh_result.tokens.refresh_token.as_str())
        .await?;
    assert_eq!(second_refresh.account.id, account.id);

    Ok(())
}

#[tokio::test]
async fn test_refresh_issues_new_tokens(
) -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "newtokens@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Login to get initial tokens
    let login_result = auth.login(email, password).await?;
    let original_access = login_result.tokens.access_token.as_str().to_string();
    let original_refresh = login_result.tokens.refresh_token.as_str().to_string();

    // Refresh should issue completely new tokens
    let refresh_result = auth.refresh(&original_refresh).await?;
    assert_ne!(refresh_result.tokens.access_token.as_str(), original_access.as_str());
    assert_ne!(refresh_result.tokens.refresh_token.as_str(), original_refresh.as_str());

    // New access token should work
    let authed_account = auth
        .authenticate_access_token(refresh_result.tokens.access_token.as_str())
        .await?;
    assert_eq!(authed_account.id, account.id);

    // Old access token should still work (until it expires)
    let old_authed = auth
        .authenticate_access_token(&original_access)
        .await?;
    assert_eq!(old_authed.id, account.id);

    Ok(())
}

#[tokio::test]
async fn test_multiple_refreshes_work(
) -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "multirefresh@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Login
    let login_result = auth.login(email, password).await?;
    let mut current_refresh = login_result.tokens.refresh_token.as_str().to_string();

    // Perform multiple refreshes
    for i in 0..5 {
        let refresh_result = auth.refresh(&current_refresh).await?;
        assert_eq!(refresh_result.account.id, account.id);
        
        // Verify new access token works
        let authed = auth
            .authenticate_access_token(refresh_result.tokens.access_token.as_str())
            .await?;
        assert_eq!(authed.id, account.id);

        // Update refresh token for next iteration
        current_refresh = refresh_result.tokens.refresh_token.as_str().to_string();
        
        // Each refresh should produce different tokens
        if i > 0 {
            assert_ne!(
                refresh_result.tokens.access_token.as_str(),
                login_result.tokens.access_token.as_str()
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_access_token_works_after_refresh(
) -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "accessafterrefresh@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Login
    let login_result = auth.login(email, password).await?;
    let original_access = login_result.tokens.access_token.as_str().to_string();

    // Refresh tokens
    let refresh_result = auth
        .refresh(login_result.tokens.refresh_token.as_str())
        .await?;

    // Original access token should still work (it hasn't expired yet)
    let authed_with_original = auth
        .authenticate_access_token(&original_access)
        .await?;
    assert_eq!(authed_with_original.id, account.id);

    // New access token should also work
    let authed_with_new = auth
        .authenticate_access_token(refresh_result.tokens.access_token.as_str())
        .await?;
    assert_eq!(authed_with_new.id, account.id);

    Ok(())
}

#[tokio::test]
async fn test_email_sent_on_registration(
) -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "emailtest@example.com";
    let password = "ComplexStr0ng!";

    // Register should trigger email sending
    let account = auth.register(email, password).await?;

    // Verify email was sent
    let (sent_to, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };

    // Check recipient
    assert_eq!(sent_to, email);
    assert_eq!(sent_to, account.email);

    // Check code format (should be 6 digits based on config)
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()), "verification code should be numeric");

    Ok(())
}

#[tokio::test]
async fn test_email_sent_for_each_registration(
) -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    // Register first account
    let email1 = "email1@example.com";
    let account1 = auth.register(email1, "ComplexStr0ng!").await?;

    // Verify first email was sent
    let (sent_to1, code1) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("first verification email was not sent")
    };
    assert_eq!(sent_to1, email1);
    assert_eq!(code1.len(), 6);

    // Register second account
    let email2 = "email2@example.com";
    let account2 = auth.register(email2, "AnotherStr0ng!").await?;

    // Verify second email was sent (should overwrite first)
    let (sent_to2, code2) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("second verification email was not sent")
    };
    assert_eq!(sent_to2, email2);
    assert_eq!(code2.len(), 6);
    assert_ne!(code1, code2, "different accounts should get different codes");

    // Verify accounts are different
    assert_ne!(account1.id, account2.id);

    Ok(())
}

#[tokio::test]
async fn test_delete_account_soft_deletes() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "delete@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Login to create tokens
    let login_result = auth.login(email, password).await?;
    let access_token = login_result.tokens.access_token.as_str().to_string();

    // Delete account
    auth.delete_account(account.id, password).await?;

    // Account should not be findable
    let result = auth.get_account(account.id).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::AccountNotFound => {}
        e => panic!("Expected AccountNotFound, got {:?}", e),
    }

    // Login should fail
    let login_result = auth.login(email, password).await;
    assert!(login_result.is_err());
    match login_result.unwrap_err() {
        iam::IamError::InvalidCredentials => {}
        e => panic!("Expected InvalidCredentials, got {:?}", e),
    }

    // Access token should still work until it expires
    let authed = auth
        .authenticate_access_token(&access_token)
        .await?;
    assert_eq!(authed.id, account.id);

    Ok(())
}

#[tokio::test]
async fn test_delete_account_invalid_password() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "delete_invalid@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Try to delete with wrong password
    let result = auth.delete_account(account.id, "WrongPassword123!").await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::InvalidCredentials => {}
        e => panic!("Expected InvalidCredentials, got {:?}", e),
    }

    // Account should still exist
    let found = auth.get_account(account.id).await?;
    assert_eq!(found.id, account.id);

    Ok(())
}

#[tokio::test]
async fn test_logout_revokes_access_token() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "logout@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Login
    let login_result = auth.login(email, password).await?;
    let access_token = login_result.tokens.access_token.as_str().to_string();

    // Access token should work
    let authed = auth.authenticate_access_token(&access_token).await?;
    assert_eq!(authed.id, account.id);

    // Logout
    auth.logout(&access_token).await?;

    // Access token should no longer work
    let result = auth.authenticate_access_token(&access_token).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::TokenExpired => {}
        e => panic!("Expected TokenExpired, got {:?}", e),
    }

    Ok(())
}

#[tokio::test]
async fn test_logout_all_revokes_all_tokens() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "logout_all@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Login multiple times to create multiple token pairs
    let login1 = auth.login(email, password).await?;
    let login2 = auth.login(email, password).await?;
    let login3 = auth.login(email, password).await?;

    let token1 = login1.tokens.access_token.as_str().to_string();
    let token2 = login2.tokens.access_token.as_str().to_string();
    let token3 = login3.tokens.access_token.as_str().to_string();

    // All tokens should work
    assert_eq!(auth.authenticate_access_token(&token1).await?.id, account.id);
    assert_eq!(auth.authenticate_access_token(&token2).await?.id, account.id);
    assert_eq!(auth.authenticate_access_token(&token3).await?.id, account.id);

    // Logout all
    auth.logout_all(account.id, password).await?;

    // All tokens should be revoked
    assert!(auth.authenticate_access_token(&token1).await.is_err());
    assert!(auth.authenticate_access_token(&token2).await.is_err());
    assert!(auth.authenticate_access_token(&token3).await.is_err());

    Ok(())
}

#[tokio::test]
async fn test_logout_all_invalid_password() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "logout_all_invalid@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Login
    let login_result = auth.login(email, password).await?;
    let access_token = login_result.tokens.access_token.as_str().to_string();

    // Try logout_all with wrong password
    let result = auth.logout_all(account.id, "WrongPassword123!").await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::InvalidCredentials => {}
        e => panic!("Expected InvalidCredentials, got {:?}", e),
    }

    // Token should still work
    let authed = auth.authenticate_access_token(&access_token).await?;
    assert_eq!(authed.id, account.id);

    Ok(())
}

#[tokio::test]
async fn test_change_password() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "changepass@example.com";
    let old_password = "ComplexStr0ng!";
    let new_password = "NewComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, old_password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Login with old password
    let login_result = auth.login(email, old_password).await?;
    let access_token = login_result.tokens.access_token.as_str().to_string();

    // Change password
    auth.change_password(account.id, old_password, new_password).await?;

    // Old password should no longer work
    let login_result = auth.login(email, old_password).await;
    assert!(login_result.is_err());
    match login_result.unwrap_err() {
        iam::IamError::InvalidCredentials => {}
        e => panic!("Expected InvalidCredentials, got {:?}", e),
    }

    // New password should work
    let login_result = auth.login(email, new_password).await?;
    assert_eq!(login_result.account.id, account.id);

    // Old access token should be revoked
    let result = auth.authenticate_access_token(&access_token).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::TokenExpired => {}
        e => panic!("Expected TokenExpired, got {:?}", e),
    }

    Ok(())
}

#[tokio::test]
async fn test_change_password_invalid_old_password() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "changepass_invalid@example.com";
    let password = "ComplexStr0ng!";
    let new_password = "NewComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Try to change password with wrong old password
    let result = auth.change_password(account.id, "WrongPassword123!", new_password).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::InvalidCredentials => {}
        e => panic!("Expected InvalidCredentials, got {:?}", e),
    }

    // Original password should still work
    let login_result = auth.login(email, password).await?;
    assert_eq!(login_result.account.id, account.id);

    Ok(())
}

#[tokio::test]
async fn test_change_password_weak_new_password() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "changepass_weak@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Try to change to weak password
    let result = auth.change_password(account.id, password, "weak").await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::WeakPassword(_) => {}
        e => panic!("Expected WeakPassword, got {:?}", e),
    }

    // Original password should still work
    let login_result = auth.login(email, password).await?;
    assert_eq!(login_result.account.id, account.id);

    Ok(())
}

#[tokio::test]
async fn test_request_password_reset() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "reset@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Request password reset
    auth.request_password_reset(email).await?;

    // Check that reset email was sent
    let (sent_to, reset_code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("password reset email was not sent")
    };
    assert_eq!(sent_to, email);
    assert_eq!(reset_code.len(), 6);

    Ok(())
}

#[tokio::test]
async fn test_request_password_reset_nonexistent_email() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, _) = setup_auth_service().await?;

    // Request reset for non-existent email
    let result = auth.request_password_reset("nonexistent@example.com").await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::AccountNotFound => {}
        e => panic!("Expected AccountNotFound, got {:?}", e),
    }

    Ok(())
}

#[tokio::test]
async fn test_reset_password() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "reset_pass@example.com";
    let old_password = "ComplexStr0ng!";
    let new_password = "NewComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, old_password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Login to create tokens
    let login_result = auth.login(email, old_password).await?;
    let access_token = login_result.tokens.access_token.as_str().to_string();

    // Request password reset
    auth.request_password_reset(email).await?;

    // Get reset code
    let (_, reset_code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("password reset email was not sent")
    };

    // Reset password
    auth.reset_password(email, &reset_code, new_password).await?;

    // Old password should no longer work
    let login_result = auth.login(email, old_password).await;
    assert!(login_result.is_err());
    match login_result.unwrap_err() {
        iam::IamError::InvalidCredentials => {}
        e => panic!("Expected InvalidCredentials, got {:?}", e),
    }

    // New password should work
    let login_result = auth.login(email, new_password).await?;
    assert_eq!(login_result.account.id, account.id);

    // Old access token should be revoked
    let result = auth.authenticate_access_token(&access_token).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::TokenExpired => {}
        e => panic!("Expected TokenExpired, got {:?}", e),
    }

    Ok(())
}

#[tokio::test]
async fn test_reset_password_invalid_code() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "reset_invalid@example.com";
    let password = "ComplexStr0ng!";
    let new_password = "NewComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Request password reset
    auth.request_password_reset(email).await?;

    // Try to reset with invalid code
    let result = auth.reset_password(email, "000000", new_password).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::InvalidVerificationCode | iam::IamError::VerificationCodeExpired => {}
        e => panic!("Expected InvalidVerificationCode or VerificationCodeExpired, got {:?}", e),
    }

    // Original password should still work
    let login_result = auth.login(email, password).await?;
    assert_eq!(login_result.account.id, account.id);

    Ok(())
}

#[tokio::test]
async fn test_reset_password_weak_password() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "reset_weak@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Request password reset
    auth.request_password_reset(email).await?;

    // Get reset code
    let (_, reset_code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("password reset email was not sent")
    };

    // Try to reset with weak password
    let result = auth.reset_password(email, &reset_code, "weak").await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::WeakPassword(_) => {}
        e => panic!("Expected WeakPassword, got {:?}", e),
    }

    // Original password should still work
    let login_result = auth.login(email, password).await?;
    assert_eq!(login_result.account.id, account.id);

    Ok(())
}

#[tokio::test]
async fn test_resend_verification_email() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "resend@example.com";
    let password = "ComplexStr0ng!";

    // Register
    let account = auth.register(email, password).await?;

    // Get first code
    let (_, code1) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };

    // Resend verification email
    auth.resend_verification_email(email).await?;

    // Get second code
    let (_, code2) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not resent")
    };

    // Codes should be different
    assert_ne!(code1, code2);

    // New code should work
    auth.verify_email(account.id, &code2).await?;

    // After verification, account should be verified
    let account_after = auth.get_account(account.id).await?;
    assert!(account_after.email_verified);

    // Old code should still work (it hasn't been consumed yet)
    // verify_email is idempotent - it will just mark as verified again
    auth.verify_email(account.id, &code1).await?;

    // Account should still be verified
    let account_final = auth.get_account(account.id).await?;
    assert!(account_final.email_verified);

    Ok(())
}

#[tokio::test]
async fn test_resend_verification_email_already_verified() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "resend_verified@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Try to resend when already verified
    let result = auth.resend_verification_email(email).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::EmailAlreadyVerified => {}
        e => panic!("Expected EmailAlreadyVerified, got {:?}", e),
    }

    Ok(())
}

#[tokio::test]
async fn test_check_email_available() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, _) = setup_auth_service().await?;

    let email = "available@example.com";

    // Email should be available before registration
    let available = auth.check_email_available(email).await?;
    assert!(available);

    // Register
    let _account = auth.register(email, "ComplexStr0ng!").await?;

    // Email should no longer be available
    let available = auth.check_email_available(email).await?;
    assert!(!available);

    Ok(())
}

#[tokio::test]
async fn test_get_account() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "getaccount@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Get account
    let found = auth.get_account(account.id).await?;
    assert_eq!(found.id, account.id);
    assert_eq!(found.email, account.email);
    assert_eq!(found.email_verified, true);

    Ok(())
}

#[tokio::test]
async fn test_get_account_not_found() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, _) = setup_auth_service().await?;

    use uuid::Uuid;
    let nonexistent_id = Uuid::new_v4();

    // Try to get non-existent account
    let result = auth.get_account(nonexistent_id).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::AccountNotFound => {}
        e => panic!("Expected AccountNotFound, got {:?}", e),
    }

    Ok(())
}

#[tokio::test]
async fn test_cleanup_expired_objects() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "cleanup@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Login to create tokens
    let _login_result = auth.login(email, password).await?;

    // Delete account (soft delete)
    auth.delete_account(account.id, password).await?;

    // Cleanup with 0-day retention (immediate deletion)
    let (_tokens, _verifications, accounts) = auth.cleanup_expired_objects(0).await?;
    
    // Should have deleted the soft-deleted account
    assert!(accounts >= 1, "Should have deleted at least one account");

    // Account should no longer exist
    let result = auth.get_account(account.id).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::AccountNotFound => {}
        e => panic!("Expected AccountNotFound, got {:?}", e),
    }

    Ok(())
}

#[tokio::test]
async fn test_cleanup_expired_objects_with_retention() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "cleanup_retention@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Delete account (soft delete)
    auth.delete_account(account.id, password).await?;

    // Cleanup with 30-day retention (should not delete yet)
    let (_tokens, _verifications, accounts) = auth.cleanup_expired_objects(30).await?;
    
    // Should not have deleted the account (it was just deleted)
    assert_eq!(accounts, 0, "Should not delete account within retention period");

    // Account should still be soft-deleted (not findable)
    let result = auth.get_account(account.id).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::AccountNotFound => {}
        e => panic!("Expected AccountNotFound, got {:?}", e),
    }

    Ok(())
}

#[tokio::test]
async fn test_get_account_after_soft_delete() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "softdelete@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Get account before deletion
    let found = auth.get_account(account.id).await?;
    assert_eq!(found.id, account.id);

    // Soft delete account
    auth.delete_account(account.id, password).await?;

    // Account should not be findable after soft delete
    let result = auth.get_account(account.id).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::AccountNotFound => {}
        e => panic!("Expected AccountNotFound, got {:?}", e),
    }

    Ok(())
}

#[tokio::test]
async fn test_check_email_available_after_soft_delete() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;

    let email = "softdelete_check@example.com";
    let password = "ComplexStr0ng!";

    // Register and verify
    let account = auth.register(email, password).await?;
    let (_, code) = {
        let guard = sent_codes
            .lock()
            .expect("poisoned TestEmailSender mutex");
        guard
            .clone()
            .expect("verification email was not sent")
    };
    auth.verify_email(account.id, &code).await?;

    // Email should not be available
    let available = auth.check_email_available(email).await?;
    assert!(!available);

    // Soft delete account
    auth.delete_account(account.id, password).await?;

    // Email should still not be available (soft-deleted accounts are filtered out)
    let available = auth.check_email_available(email).await?;
    assert!(!available);

    // Small delay to ensure deleted_at timestamp is in the past
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Cleanup with 0-day retention to permanently delete
    auth.cleanup_expired_objects(0).await?;

    // After permanent deletion, email should be available again
    let available = auth.check_email_available(email).await?;
    assert!(available);

    Ok(())
}


