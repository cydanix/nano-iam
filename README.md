## Rust IAM library

This crate provides basic email+password authentication with:

- account storage in PostgreSQL
- email verification codes
- access and refresh tokens stored in PostgreSQL and checked on each request

### Database schema (SQLx)

You can create the minimal schema with:

```sql
create table accounts (
    id uuid primary key,
    email text not null unique,
    password_hash text not null,
    email_verified boolean not null default false,
    created_at timestamptz not null,
    updated_at timestamptz not null
);

create type token_type as enum ('access', 'refresh');

create table tokens (
    id uuid primary key,
    account_id uuid not null references accounts(id) on delete cascade,
    token text not null unique,
    token_type token_type not null,
    expires_at timestamptz not null,
    created_at timestamptz not null,
    revoked_at timestamptz
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

### Public API

Main types to use:

- `AuthService`: main entry point (takes `EmailSender` instance as parameter)
- `AuthConfig`, `TokenConfig`, `EmailVerificationConfig`, `PasswordPolicy`: configuration
- `LoginResult`, `RefreshResult`
- `Account`, `AccountId`

Construct the service (example with SQLx and lettre):

```rust
use std::sync::Arc;

use iam::{
    AuthConfig,
    AuthService,
    EmailVerificationConfig,
    TokenConfig,
    PasswordPolicy,
};
use iam::email::LettreEmailSender;
use iam::repo::Repo;
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

    let repo = Repo::new(pool);

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

    Ok(AuthService::new(repo, email_sender, cfg))
}
```

### Typical flows

#### Register account

```rust
let account = auth_service
    .register("user@example.com", "password123")
    .await?;
```

This will:

- create the account row
- generate an email verification code and row
- send an email with that code using `EmailSender`

#### Verify email

```rust
auth_service
    .verify_email(account.id, "123456")
    .await?;
```

#### Login

```rust
let LoginResult { account, tokens } = auth_service
    .login("user@example.com", "password123")
    .await?;

// Use tokens.access_token as bearer token in API responses
// Store tokens.refresh_token in http-only cookie or secure storage on client
```

#### Authenticate API request (access token)

```rust
let account = auth_service
    .authenticate_access_token(access_token_from_header)
    .await?;

// account.id identifies the current user
```

#### Refresh tokens

```rust
let RefreshResult { account, tokens } = auth_service
    .refresh(refresh_token_from_cookie)
    .await?;
```

This will:

- validate the refresh token
- revoke the old refresh token
- issue new access and refresh tokens


