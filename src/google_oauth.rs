use std::env;
use tracing::{error, warn};
use serde::Deserialize;
use crate::errors::IamError;

#[derive(Debug, Deserialize)]
struct GoogleTokenInfo {
    email: String,
    email_verified: bool,
    aud: Option<String>, // Audience (client_id)
    #[allow(dead_code)]
    sub: String, // Subject (user ID) - kept for potential future use
}

/// Verify Google ID token and extract email
/// 
/// This function validates a Google ID token and extracts the verified email address.
/// It uses Google's tokeninfo endpoint for validation.
/// 
/// # Parameters
/// - `id_token`: The Google ID token to verify
/// 
/// # Returns
/// The verified email address if the token is valid
/// 
/// # Errors
/// Returns `IamError::InvalidOAuthToken` if the token is invalid
/// Returns `IamError::OAuthEmailNotVerified` if the email is not verified by Google
pub async fn verify_google_id_token(id_token: &str) -> Result<String, IamError> {
    verify_google_id_token_with_base_url(id_token, "https://oauth2.googleapis.com").await
}

/// Verify Google ID token with a custom base URL (for testing)
/// 
/// This is a test-only function that allows injecting a custom base URL
/// to mock Google's tokeninfo endpoint in tests.
#[doc(hidden)]
pub async fn verify_google_id_token_with_base_url(
    id_token: &str,
    base_url: &str,
) -> Result<String, IamError> {
    let client_id = env::var("GOOGLE_OAUTH_CLIENT_ID")
        .map_err(|_| {
            error!("GOOGLE_OAUTH_CLIENT_ID environment variable not set");
            IamError::InvalidOAuthToken
        })?;

    // Use Google's tokeninfo endpoint to validate the token
    let url = format!("{}/tokeninfo?id_token={}", base_url, id_token);
    
    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to verify Google token");
            IamError::InvalidOAuthToken
        })?;

    if !response.status().is_success() {
        warn!("Google token validation failed with status: {}", response.status());
        return Err(IamError::InvalidOAuthToken);
    }

    let token_info: GoogleTokenInfo = response
        .json()
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to parse Google token response");
            IamError::InvalidOAuthToken
        })?;

    // Verify the audience (client_id) matches if present
    if let Some(ref aud) = token_info.aud {
        if aud != &client_id {
            warn!("Google token audience mismatch: expected {}, got {}", client_id, aud);
            return Err(IamError::InvalidOAuthToken);
        }
    }
    
    // Check if email is verified
    if !token_info.email_verified {
        warn!("Google account email not verified");
        return Err(IamError::OAuthEmailNotVerified);
    }

    Ok(token_info.email)
}
