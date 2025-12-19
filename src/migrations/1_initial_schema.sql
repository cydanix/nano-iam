-- Initial schema for nano-iam
-- This migration creates all required tables and types for the IAM service

-- Create enum types
CREATE TYPE token_type AS ENUM ('access', 'refresh');

CREATE TYPE auth_type AS ENUM ('email', 'google');

-- Create accounts table
CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    auth_type auth_type NOT NULL DEFAULT 'email',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ
);

-- Create tokens table
CREATE TABLE tokens (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    token_type token_type NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    root_token TEXT,
    usage BIGINT NOT NULL DEFAULT 0
);

-- Create email_verifications table
CREATE TABLE email_verifications (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);

-- Create indexes for better query performance
CREATE INDEX idx_tokens_account_id ON tokens(account_id);
CREATE INDEX idx_tokens_token ON tokens(token);
CREATE INDEX idx_tokens_root_token ON tokens(root_token) WHERE root_token IS NOT NULL;
CREATE INDEX idx_tokens_expires_at ON tokens(expires_at);
CREATE INDEX idx_tokens_revoked_at ON tokens(revoked_at) WHERE revoked_at IS NOT NULL;

CREATE INDEX idx_email_verifications_account_id ON email_verifications(account_id);
CREATE INDEX idx_email_verifications_code ON email_verifications(code);
CREATE INDEX idx_email_verifications_expires_at ON email_verifications(expires_at);

CREATE INDEX idx_accounts_email ON accounts(email);
CREATE INDEX idx_accounts_deleted_at ON accounts(deleted_at) WHERE deleted_at IS NOT NULL;

