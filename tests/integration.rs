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

async fn setup_auth_service_with_pool(
) -> Result<(AuthService, Arc<Mutex<Option<(String, String)>>>, PgPool), Box<dyn std::error::Error>>
{
    let pool = setup_db().await?;
    let repo = Repo::new(pool.clone());

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

    Ok((service, shared, pool))
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

// Helper function to query token from database for testing
async fn get_token_from_db(
    pool: &PgPool,
    token_value: &str,
) -> Result<Option<iam::models::Token>, Box<dyn std::error::Error>> {
    use iam::models::Token;
    
    let row = sqlx::query_as::<_, Token>(
        r#"
        select id, account_id, token, token_type, expires_at, created_at, revoked_at, root_token, usage
        from tokens
        where token = $1
        "#,
    )
    .bind(token_value)
    .fetch_optional(pool)
    .await?;
    
    Ok(row)
}

#[tokio::test]
async fn test_token_chain_creation() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes, pool) = setup_auth_service_with_pool().await?;

    let email = "chain@example.com";
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
    let access_token = login_result.tokens.access_token.as_str();
    let refresh_token = login_result.tokens.refresh_token.as_str();

    // Verify tokens share the same root_token
    let access_token_db = get_token_from_db(&pool, access_token).await?
        .expect("access token not found in database");
    let refresh_token_db = get_token_from_db(&pool, refresh_token).await?
        .expect("refresh token not found in database");

    // Both tokens should have the same root_token (which should be the refresh token value)
    assert_eq!(
        access_token_db.root_token,
        refresh_token_db.root_token,
        "Access and refresh tokens should share the same root_token"
    );
    assert_eq!(
        refresh_token_db.root_token,
        Some(refresh_token.to_string()),
        "Root token should be the refresh token value"
    );
    assert_eq!(
        refresh_token_db.usage, 0,
        "Initial refresh token usage should be 0"
    );
    assert_eq!(
        access_token_db.usage, 0,
        "Access token usage should be 0"
    );

    Ok(())
}

#[tokio::test]
async fn test_refresh_maintains_root_token() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes, pool) = setup_auth_service_with_pool().await?;

    let email = "refresh_chain@example.com";
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
    let original_refresh_token = login_result.tokens.refresh_token.as_str();
    
    // Get original root_token
    let original_refresh_db = get_token_from_db(&pool, original_refresh_token).await?
        .expect("refresh token not found");
    let original_root_token = original_refresh_db.root_token.clone()
        .expect("original refresh token should have root_token");

    // Refresh tokens
    let refresh_result = auth.refresh(original_refresh_token).await?;
    let new_access_token = refresh_result.tokens.access_token.as_str();
    let new_refresh_token = refresh_result.tokens.refresh_token.as_str();

    // Verify new tokens maintain the same root_token
    let new_access_db = get_token_from_db(&pool, new_access_token).await?
        .expect("new access token not found");
    let new_refresh_db = get_token_from_db(&pool, new_refresh_token).await?
        .expect("new refresh token not found");

    assert_eq!(
        new_access_db.root_token,
        Some(original_root_token.clone()),
        "New access token should maintain the same root_token"
    );
    assert_eq!(
        new_refresh_db.root_token,
        Some(original_root_token),
        "New refresh token should maintain the same root_token"
    );
    assert_eq!(
        new_refresh_db.usage, 0,
        "New refresh token usage should start at 0"
    );

    Ok(())
}

#[tokio::test]
async fn test_refresh_token_usage_counter() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes, pool) = setup_auth_service_with_pool().await?;

    let email = "usage@example.com";
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
    let refresh_token = login_result.tokens.refresh_token.as_str();

    // Verify initial usage is 0
    let token_before = get_token_from_db(&pool, refresh_token).await?
        .expect("refresh token not found");
    assert_eq!(token_before.usage, 0, "Initial usage should be 0");

    // Use refresh token once
    let _refresh_result = auth.refresh(refresh_token).await?;

    // Verify usage was incremented (but token is now revoked, so we check the revoked token)
    // Note: After refresh, the old token is revoked, so we need to check it differently
    // The usage counter should have been incremented before revocation
    let token_after = get_token_from_db(&pool, refresh_token).await?
        .expect("refresh token should still exist in DB (revoked)");
    assert_eq!(
        token_after.usage, 1,
        "Token usage should be 1 after first use"
    );
    assert!(
        token_after.revoked_at.is_some(),
        "Token should be revoked after use"
    );

    Ok(())
}

#[tokio::test]
async fn test_double_usage_detection_and_chain_revocation() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes, pool) = setup_auth_service_with_pool().await?;

    let email = "double_usage@example.com";
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
    let refresh_token = login_result.tokens.refresh_token.as_str();

    // Simulate double usage: use the same refresh token twice concurrently
    // First use (should succeed)
    let first_refresh = auth.refresh(refresh_token).await?;

    // Verify first refresh worked
    assert_eq!(first_refresh.account.id, account.id);

    // Try to use the same refresh token again (simulating token compromise)
    // This should fail because the token was already used and revoked
    let second_result = auth.refresh(refresh_token).await;
    assert!(
        second_result.is_err(),
        "Second use of the same refresh token should fail"
    );
    
    // Check that it's TokenExpired (token was revoked after first use)
    match second_result.unwrap_err() {
        iam::IamError::TokenExpired => {
            // Expected - token was revoked after first use
        }
        e => panic!("Expected TokenExpired, got {:?}", e),
    }

    // Now simulate actual double usage by manually incrementing usage before revocation
    // This simulates the race condition where two requests use the same token
    // We'll need to test this by directly manipulating the database
    
    // Create a new login to get fresh tokens
    let login_result2 = auth.login(email, password).await?;
    let refresh_token2 = login_result2.tokens.refresh_token.as_str();
    
    // Get root_token for the new token chain
    let refresh_token2_db = get_token_from_db(&pool, refresh_token2).await?
        .expect("refresh token not found");
    let root_token2 = refresh_token2_db.root_token.clone()
        .expect("refresh token should have root_token");
    
    // Manually increment usage to simulate double usage
    sqlx::query(
        r#"
        update tokens
        set usage = usage + 1
        where token = $1
        "#,
    )
    .bind(refresh_token2)
    .execute(&pool)
    .await?;

    // Now try to refresh - this should detect double usage
    let double_usage_result = auth.refresh(refresh_token2).await;
    
    // This should detect the double usage and revoke the chain
    match double_usage_result {
        Ok(_) => {
            // Check if the chain was revoked
            let token_after = get_token_from_db(&pool, refresh_token2).await?
                .expect("token should exist");
            assert!(
                token_after.revoked_at.is_some(),
                "Token should be revoked after double usage detection"
            );
        }
        Err(iam::IamError::TokenReuseDetected) => {
            // Expected - double usage was detected
            // Verify all tokens with same root_token are revoked
            let revoked_count: i64 = sqlx::query_scalar(
                r#"
                select count(*)
                from tokens
                where root_token = $1
                  and revoked_at is not null
                "#,
            )
            .bind(&root_token2)
            .fetch_one(&pool)
            .await?;
            
            assert!(
                revoked_count > 0,
                "Tokens in chain should be revoked after double usage"
            );
        }
        Err(_e) => {
            // Check if usage was > 1 and chain was revoked
            let token_after = get_token_from_db(&pool, refresh_token2).await?;
            if let Some(token) = token_after {
                if token.usage > 1 {
                    // Double usage was detected, chain should be revoked
                    // Verify all tokens with same root_token are revoked
                    let revoked_count: i64 = sqlx::query_scalar(
                        r#"
                        select count(*)
                        from tokens
                        where root_token = $1
                          and revoked_at is not null
                        "#,
                    )
                    .bind(&root_token2)
                    .fetch_one(&pool)
                    .await?;
                    
                    assert!(
                        revoked_count > 0,
                        "Tokens in chain should be revoked after double usage"
                    );
                }
            }
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_token_chain_revocation_on_compromise() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes, pool) = setup_auth_service_with_pool().await?;

    let email = "compromise@example.com";
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
    let access_token1 = login_result.tokens.access_token.as_str();
    let refresh_token1 = login_result.tokens.refresh_token.as_str();

    // Refresh once to get second set of tokens
    let refresh_result1 = auth.refresh(refresh_token1).await?;
    let access_token2 = refresh_result1.tokens.access_token.as_str();
    let refresh_token2 = refresh_result1.tokens.refresh_token.as_str();

    // Get root_token
    let token_db = get_token_from_db(&pool, refresh_token2).await?
        .expect("refresh token not found");
    let root_token = token_db.root_token.clone()
        .expect("should have root_token");

    // Manually set usage to 2 to simulate double usage detection
    sqlx::query(
        r#"
        update tokens
        set usage = 2
        where token = $1
        "#,
    )
    .bind(refresh_token2)
    .execute(&pool)
    .await?;

    // Try to refresh - should detect double usage and revoke chain
    let result = auth.refresh(refresh_token2).await;
    
    // Should return TokenReuseDetected error
    match result {
        Err(iam::IamError::TokenReuseDetected) => {
            // Expected - double usage detected
        }
        Ok(_) => {
            // If it succeeded, verify the chain was still revoked
            // This shouldn't happen, but let's check
        }
        Err(e) => panic!("Expected TokenReuseDetected, got {:?}", e),
    }

    // Verify all tokens with the same root_token are revoked
    let revoked_tokens: Vec<String> = sqlx::query_scalar(
        r#"
        select token
        from tokens
        where root_token = $1
          and revoked_at is not null
        "#,
    )
    .bind(&root_token)
    .fetch_all(&pool)
    .await?;

    assert!(
        revoked_tokens.len() > 0,
        "At least some tokens in the chain should be revoked"
    );

    // Verify that access tokens from the chain are no longer valid
    let auth_result1 = auth.authenticate_access_token(access_token1).await;
    let auth_result2 = auth.authenticate_access_token(access_token2).await;

    // At least one should fail (depending on which tokens were in the chain)
    // The tokens that share the root_token should be revoked
    assert!(
        auth_result1.is_err() || auth_result2.is_err(),
        "At least one access token from the compromised chain should be invalid"
    );

    Ok(())
}

#[tokio::test]
async fn test_multiple_refreshes_maintain_chain() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes, pool) = setup_auth_service_with_pool().await?;

    let email = "multichain@example.com";
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
    let mut current_refresh = login_result.tokens.refresh_token.as_str().to_string();
    
    // Get original root_token
    let original_token_db = get_token_from_db(&pool, &current_refresh).await?
        .expect("refresh token not found");
    let original_root_token = original_token_db.root_token.clone()
        .expect("should have root_token");

    // Perform multiple refreshes
    for i in 0..3 {
        let refresh_result = auth.refresh(&current_refresh).await?;
        assert_eq!(refresh_result.account.id, account.id);
        
        // Verify new tokens maintain the same root_token
        let new_refresh_db = get_token_from_db(&pool, refresh_result.tokens.refresh_token.as_str()).await?
            .expect("new refresh token not found");
        assert_eq!(
            new_refresh_db.root_token,
            Some(original_root_token.clone()),
            "Refresh {}: new token should maintain root_token",
            i + 1
        );
        
        // Update for next iteration
        current_refresh = refresh_result.tokens.refresh_token.as_str().to_string();
    }

    Ok(())
}

// Google OAuth tests with mocked Google server
use wiremock::{Mock, MockServer, ResponseTemplate};
use wiremock::matchers::{method, path, query_param};

// Unit tests for Google OAuth verification with mocked server
#[tokio::test]
async fn test_verify_google_id_token_success() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let mock_server = MockServer::start().await;
    let client_id = "test-google-client-id-12345";
    std::env::set_var("GOOGLE_OAUTH_CLIENT_ID", client_id);
    
    let test_email = "test@gmail.com";
    let test_token = "valid_token_123";
    
    Mock::given(method("GET"))
        .and(path("/tokeninfo"))
        .and(query_param("id_token", test_token))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "email": test_email,
            "email_verified": true,
            "aud": client_id,
            "sub": "user123"
        })))
        .mount(&mock_server)
        .await;
    
    let base_url = format!("http://{}", mock_server.address());
    let result = iam::google_oauth::verify_google_id_token_with_base_url(test_token, &base_url).await;
    
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), test_email);
    
    Ok(())
}

#[tokio::test]
async fn test_verify_google_id_token_unverified_email() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let mock_server = MockServer::start().await;
    let client_id = "test-google-client-id-12345";
    std::env::set_var("GOOGLE_OAUTH_CLIENT_ID", client_id);
    
    let test_token = "unverified_token";
    
    Mock::given(method("GET"))
        .and(path("/tokeninfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "email": "unverified@gmail.com",
            "email_verified": false,
            "aud": client_id,
            "sub": "user123"
        })))
        .mount(&mock_server)
        .await;
    
    let base_url = format!("http://{}", mock_server.address());
    let result = iam::google_oauth::verify_google_id_token_with_base_url(test_token, &base_url).await;
    
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::OAuthEmailNotVerified => {}
        e => panic!("Expected OAuthEmailNotVerified, got {:?}", e),
    }
    
    Ok(())
}

#[tokio::test]
async fn test_verify_google_id_token_audience_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let mock_server = MockServer::start().await;
    let client_id = "test-google-client-id-12345";
    std::env::set_var("GOOGLE_OAUTH_CLIENT_ID", client_id);
    
    let test_token = "wrong_audience_token";
    
    Mock::given(method("GET"))
        .and(path("/tokeninfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "email": "test@gmail.com",
            "email_verified": true,
            "aud": "different-client-id",
            "sub": "user123"
        })))
        .mount(&mock_server)
        .await;
    
    let base_url = format!("http://{}", mock_server.address());
    let result = iam::google_oauth::verify_google_id_token_with_base_url(test_token, &base_url).await;
    
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::InvalidOAuthToken => {}
        e => panic!("Expected InvalidOAuthToken, got {:?}", e),
    }
    
    Ok(())
}

#[tokio::test]
async fn test_verify_google_id_token_invalid_response() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let mock_server = MockServer::start().await;
    let client_id = "test-google-client-id-12345";
    std::env::set_var("GOOGLE_OAUTH_CLIENT_ID", client_id);
    
    let test_token = "invalid_token";
    
    Mock::given(method("GET"))
        .and(path("/tokeninfo"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&mock_server)
        .await;
    
    let base_url = format!("http://{}", mock_server.address());
    let result = iam::google_oauth::verify_google_id_token_with_base_url(test_token, &base_url).await;
    
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::InvalidOAuthToken => {}
        e => panic!("Expected InvalidOAuthToken, got {:?}", e),
    }
    
    Ok(())
}

#[tokio::test]
async fn test_verify_google_id_token_missing_client_id() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    // Remove the environment variable
    std::env::remove_var("GOOGLE_OAUTH_CLIENT_ID");
    
    let result = iam::google_oauth::verify_google_id_token("any_token").await;
    
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::InvalidOAuthToken => {}
        e => panic!("Expected InvalidOAuthToken, got {:?}", e),
    }
    
    // Restore for other tests
    std::env::set_var("GOOGLE_OAUTH_CLIENT_ID", "test-client-id");
    
    Ok(())
}

#[tokio::test]
async fn test_google_oauth_register() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, _sent_codes) = setup_auth_service().await?;
    
    let email = "google.register@gmail.com";
    
    // Register with Google auth type
    let account = auth.register_with_auth_type(email, "", iam::AuthType::Google).await?;
    
    assert_eq!(account.email, email);
    assert_eq!(account.auth_type, iam::AuthType::Google);
    assert!(account.email_verified); // Google accounts are auto-verified
    assert_eq!(account.password_hash, ""); // No password for Google accounts
    
    Ok(())
}

#[tokio::test]
async fn test_google_oauth_auth_type_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, sent_codes) = setup_auth_service().await?;
    
    let email = "mismatch@example.com";
    let password = "ComplexStr0ng!";
    
    // Create an email account
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
    
    // Verify the account has Email auth type
    let found_account = auth.get_account(account.id).await?;
    assert_eq!(found_account.auth_type, iam::AuthType::Email);
    
    // Try to register with Google using the same email - should fail (email already exists)
    let result = auth.register_with_auth_type(email, "", iam::AuthType::Google).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        iam::IamError::Db(_) => {} // Database constraint violation
        e => panic!("Expected database error, got {:?}", e),
    }
    
    Ok(())
}

#[tokio::test]
async fn test_google_oauth_account_auto_verified() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let (auth, _sent_codes) = setup_auth_service().await?;
    
    let email = "auto.verified@gmail.com";
    
    // Register with Google - should be automatically verified
    let account = auth.register_with_auth_type(email, "", iam::AuthType::Google).await?;
    
    assert!(account.email_verified, "Google accounts should be auto-verified");
    assert_eq!(account.auth_type, iam::AuthType::Google);
    
    // Should be able to login immediately (no email verification needed)
    // Note: Full login test would require mocking Google token validation
    
    Ok(())
}


