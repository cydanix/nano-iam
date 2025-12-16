use std::sync::{Arc, Mutex};

use chrono::Duration;
use iam::{
    AuthConfig,
    AuthService,
    EmailVerificationConfig,
    TokenConfig,
};
use iam::email::EmailSender;
use iam::repo::Repo;
use async_trait::async_trait;
use sqlx::postgres::PgPoolOptions;
use sqlx::Pool;
use sqlx::Postgres;

type PgPool = Pool<Postgres>;

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

    // Minimal schema for tests; matches README.md
    // Drop and recreate all objects for clean test isolation
    // Use a single DO block to handle everything atomically and handle race conditions
    sqlx::query(
        r#"
do $$
begin
    -- Drop tables first (they depend on the enum type)
    drop table if exists email_verifications cascade;
    drop table if exists tokens cascade;
    drop table if exists accounts cascade;
    
    -- Drop enum type if it exists (CASCADE will drop dependent objects)
    drop type if exists token_type cascade;
    
    -- Create enum type (handle race condition where another test already created it)
    -- Check if type exists first to avoid errors
    if not exists (
        select 1 from pg_type 
        where typname = 'token_type' 
        and typtype = 'e'
    ) then
        begin
            create type token_type as enum ('access', 'refresh');
        exception
            when duplicate_object then
                null; -- Type already exists, that's fine
            when others then
                -- Check if it's a constraint violation (type already exists)
                if sqlstate = '23505' or sqlstate = '42710' then
                    null;
                else
                    raise;
                end if;
        end;
    end if;
    
    -- Create tables (use IF NOT EXISTS to handle race conditions)
    create table if not exists accounts (
        id uuid primary key,
        email text not null unique,
        password_hash text not null,
        email_verified boolean not null default false,
        created_at timestamptz not null,
        updated_at timestamptz not null
    );
    
    create table if not exists tokens (
        id uuid primary key,
        account_id uuid not null references accounts(id) on delete cascade,
        token text not null unique,
        token_type token_type not null,
        expires_at timestamptz not null,
        created_at timestamptz not null,
        revoked_at timestamptz
    );
    
    create table if not exists email_verifications (
        id uuid primary key,
        account_id uuid not null references accounts(id) on delete cascade,
        code text not null,
        expires_at timestamptz not null,
        consumed_at timestamptz,
        created_at timestamptz not null
    );
end
$$;
        "#,
    )
    .execute(&pool)
    .await?;

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


