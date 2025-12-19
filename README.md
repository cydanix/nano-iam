# nano-iam

A lightweight, production-ready Rust library for Identity and Access Management (IAM) with PostgreSQL backend. Provides secure authentication, token management, and email verification for modern applications.

## Features

- **Multiple Authentication Methods**
  - Email and password authentication with Argon2 password hashing
  - Google OAuth integration via ID token verification
  - Configurable password policies with complexity requirements

- **Token Management**
  - JWT-based access and refresh tokens
  - Token storage in PostgreSQL for revocation and validation
  - Automatic token expiration and refresh flow
  - Protection against token reuse attacks

- **Email Verification**
  - Time-limited verification codes
  - Automatic email sending via configurable `EmailSender` trait
  - Built-in support for Lettre SMTP transport

- **Database Integration**
  - PostgreSQL storage with SQLx
  - Programmatic schema creation
  - Support for master-slave database setups

- **Distributed System Support**
  - PostgreSQL advisory locks for distributed deployments
  - Prevents race conditions in token refresh, email verification, and password reset
  - Supports master-slave PostgreSQL setups

- **Production Ready**
  - Automatic retry logic for transient database errors
  - Comprehensive error handling
  - Structured logging with tracing
  - Configurable TTLs and security policies

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
nano-iam = { path = "../nano-iam" }
# Or from crates.io when published
# nano-iam = "0.1.0"
```

## Database Schema

### Using Migrations (Recommended)

The recommended way to set up the database schema is using SQLx migrations:

```rust
use nano_iam::repo::Repo;
use sqlx::postgres::PgPoolOptions;

async fn setup_database(database_url: &str) -> anyhow::Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;
    
    let repo = Repo::new(pool);
    repo.migrate().await?;
    
    Ok(())
}
```

Migrations are located in the `src/migrations/` directory and are automatically applied when you call `migrate()`. The migration system uses PostgreSQL advisory locks to ensure only one instance runs migrations at a time.

### Manual Schema Creation (Deprecated)

Alternatively, you can create the schema manually with SQL:

```sql
create type token_type as enum ('access', 'refresh');

create table accounts (
    id uuid primary key,
    email text not null unique,
    password_hash text not null,
    email_verified boolean not null default false,
    auth_type text not null default 'email',
    created_at timestamptz not null,
    updated_at timestamptz not null,
    deleted_at timestamptz
);

create table tokens (
    id uuid primary key,
    account_id uuid not null references accounts(id) on delete cascade,
    token text not null unique,
    token_type token_type not null,
    expires_at timestamptz not null,
    created_at timestamptz not null,
    revoked_at timestamptz,
    root_token text,
    usage bigint not null default 0
);

create table email_verifications (
    id uuid primary key,
    account_id uuid not null references accounts(id) on delete cascade,
    code text not null,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    created_at timestamptz not null
);
```

**Note:** The `migrate()` method is idempotent and can be called multiple times safely.

## Public API

Main types to use:

- `AuthService`: main entry point (takes `EmailSender` instance as parameter)
- `AuthConfig`, `TokenConfig`, `EmailVerificationConfig`, `PasswordPolicy`: configuration
- `LoginResult`, `RefreshResult`
- `Account`, `AccountId`

## Setup

Construct the service (example with SQLx and lettre):

```rust
use std::sync::Arc;

use nano_iam::{
    AuthConfig,
    AuthService,
    EmailVerificationConfig,
    TokenConfig,
    PasswordPolicy,
};
use nano_iam::email::LettreEmailSender;
use nano_iam::repo::Repo;
use chrono::Duration;
use lettre::message::Mailbox;
use lettre::AsyncSmtpTransport;
use lettre::Tokio1Executor;
use sqlx::postgres::PgPoolOptions;

async fn build_auth_service(database_url: &str) -> anyhow::Result<AuthService> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;

    let repo = Repo::new(pool.clone());
    
    // Create lock for distributed deployment (required)
    let lock = nano_iam::locks::LeaseLock::new(pool);

    let transport = AsyncSmtpTransport::<Tokio1Executor>::relay("smtp.example.com")?
        .build();

    let from: Mailbox = "Auth <no-reply@example.com>".parse()?;
    let email_sender = Arc::new(LettreEmailSender::new(transport, from));

    let cfg = AuthConfig {
        token: TokenConfig {
            access_ttl: Duration::minutes(15),
            refresh_ttl: Duration::days(30),
        },
        email_verification: EmailVerificationConfig {
            code_ttl: Duration::minutes(10),
            code_length: 6,
        },
        password_policy: PasswordPolicy::default(), // Or customize password requirements
        service_name: None, // Optional service name for email templates
    };

    Ok(AuthService::new(repo, email_sender, cfg, lock))
}
```

**Note:** Locks are required for distributed PostgreSQL deployments to prevent race conditions in critical operations like token refresh, email verification, and password reset.

## Typical Flows

### Register Account (Email/Password)

```rust
let account = auth_service
    .register("user@example.com", "password123")
    .await?;
```

This will:

- create the account row
- generate an email verification code and row
- send an email with that code using `EmailSender`

### Register Account (Google OAuth)

```rust
use nano_iam::models::AuthType;

// Verify Google ID token first
let email = nano_iam::google_oauth::verify_google_id_token(id_token).await?;

// Register with Google auth type
let account = auth_service
    .register_with_auth_type(&email, "", AuthType::Google)
    .await?;
```

**Note:** Set the `GOOGLE_OAUTH_CLIENT_ID` environment variable for OAuth verification.

### Verify Email

```rust
auth_service
    .verify_email(account.id, "123456")
    .await?;
```

### Login

```rust
let LoginResult { account, tokens } = auth_service
    .login("user@example.com", "password123")
    .await?;

// Use tokens.access_token as bearer token in API responses
// Store tokens.refresh_token in http-only cookie or secure storage on client
```

### Authenticate API Request (Access Token)

```rust
let account = auth_service
    .authenticate_access_token(access_token_from_header)
    .await?;

// account.id identifies the current user
```

### Refresh Tokens

```rust
let RefreshResult { account, tokens } = auth_service
    .refresh(refresh_token_from_cookie)
    .await?;
```

This will:

- validate the refresh token
- revoke the old refresh token
- issue new access and refresh tokens

## Configuration

### Password Policy

Customize password requirements:

```rust
let password_policy = PasswordPolicy {
    min_length: 12,
    require_uppercase: true,
    require_lowercase: true,
    require_digit: true,
    require_special: true,
    block_common_passwords: true,
};
```

### Token Configuration

Adjust token lifetimes:

```rust
let token_config = TokenConfig {
    access_ttl: Duration::minutes(15),   // Short-lived access tokens
    refresh_ttl: Duration::days(30),      // Longer-lived refresh tokens
};
```

### Email Verification

Configure verification code settings:

```rust
let email_verification_config = EmailVerificationConfig {
    code_ttl: Duration::minutes(10),      // Code expiration time
    code_length: 6,                        // Code length (numeric)
};
```

## Distributed Deployments

This library is designed for distributed PostgreSQL deployments and uses advisory locks to prevent race conditions:

- **Token Refresh**: Prevents double-spending the same refresh token
- **Email Verification**: Prevents using the same verification code twice
- **Password Reset**: Prevents using the same reset code twice
- **Google OAuth Account Creation**: Prevents duplicate account creation
- **Change Password**: Prevents concurrent password changes causing inconsistent state
- **Cleanup Expired Objects**: Prevents multiple cleanup jobs running simultaneously

### Master-Slave PostgreSQL Setup

When using master-slave PostgreSQL:
- **Always use the master database connection for locks**
- Read replicas cannot acquire advisory locks
- All lock operations must go through the master
- Use the same database pool for both `Repo` and `LeaseLock`

## Error Handling

The library uses `IamError` for all error cases:

```rust
use nano_iam::IamError;

match auth_service.login(email, password).await {
    Ok(result) => { /* success */ }
    Err(IamError::InvalidCredentials) => { /* wrong password */ }
    Err(IamError::AccountNotFound) => { /* email not found */ }
    Err(IamError::WeakPassword(msg)) => { /* password doesn't meet policy */ }
    Err(e) => { /* other error */ }
}
```

## License

MIT
