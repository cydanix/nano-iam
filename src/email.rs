use std::time::Duration;

use async_trait::async_trait;
use lettre::message::{Mailbox, Message};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use tokio::time::timeout;
use tracing::{error, debug};

use crate::errors::IamError;

#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub address: String,
    pub username: String,
    pub password: String,
    pub server: String,
    pub port: u16,
    pub service_name: Option<String>,
}

#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send_verification_email(
        &self,
        to: &str,
        code: &str,
        service_name: Option<&str>,
    ) -> Result<(), IamError>;

    async fn send_password_reset_email(
        &self,
        to: &str,
        code: &str,
        service_name: Option<&str>,
    ) -> Result<(), IamError>;
}

#[derive(Debug)]
pub struct LettreEmailSender {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    service_name: Option<String>,
    #[allow(dead_code)] // Stored for reference; actual timeout configured on transport builder
    connection_timeout: Duration,
    send_timeout: Duration,
}

impl LettreEmailSender {
    pub fn new(
        transport: AsyncSmtpTransport<Tokio1Executor>,
        from: Mailbox,
        service_name: Option<String>,
    ) -> Self {
        Self {
            transport,
            from,
            service_name,
            connection_timeout: Duration::from_secs(5),
            send_timeout: Duration::from_secs(20),
        }
    }

    /// Create a new LettreEmailSender configured for Office365 SMTP
    /// 
    /// Uses STARTTLS authentication.
    /// 
    /// # Parameters
    /// - `config`: Email configuration containing address, username, password, server, and port
    pub fn new_office365(config: &EmailConfig) -> Result<Self, IamError> {
        let from: Mailbox = config.address
            .parse()
            .map_err(|e: lettre::address::AddressError| {
                error!(address = %config.address, error = %e, "Failed to parse from address");
                IamError::Email(format!("Failed to parse from address: {}", e))
            })?;

        let credentials = Credentials::new(config.username.clone(), config.password.clone());

        let connection_timeout = Duration::from_secs(5);
        let send_timeout = Duration::from_secs(20);

        // Note: lettre's timeout() sets timeout for entire SMTP operation (connection + send)
        // We set it to send_timeout (20s) to cover the full operation
        // Connection should ideally complete within connection_timeout (5s)
        let transport = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.server)
            .map_err(|e| {
                error!(server = %config.server, error = %e, "Failed to create SMTP relay");
                IamError::Email(format!("Failed to create SMTP relay: {}", e))
            })?
            .port(config.port)
            .credentials(credentials)
            .timeout(Some(send_timeout))
            .build();

        debug!(
            server = %config.server,
            port = config.port,
            from = %config.address,
            service_name = ?config.service_name,
            connection_timeout_secs = connection_timeout.as_secs(),
            send_timeout_secs = send_timeout.as_secs(),
            "Configured Office365 SMTP transport"
        );

        Ok(Self {
            transport,
            from,
            service_name: config.service_name.clone(),
            connection_timeout,
            send_timeout,
        })
    }
}

#[async_trait]
impl EmailSender for LettreEmailSender {
    async fn send_verification_email(
        &self,
        to: &str,
        code: &str,
        service_name: Option<&str>,
    ) -> Result<(), IamError> {
        debug!(to = %to, "Sending verification email");
        let to_mailbox: Mailbox = to
            .parse()
            .map_err(|e: lettre::address::AddressError| {
                error!(to = %to, error = %e, "Failed to parse email address");
                IamError::Email(e.to_string())
            })?;

        let service_name = service_name
            .or_else(|| self.service_name.as_deref())
            .unwrap_or("Our Service");
        
        let subject = format!("Your {} verification code", service_name);
        let body = format!(
            "Hello,\n\nYour verification code for {} is: {}\n\nThis code will expire in a few minutes.\n\nIf you didn't request this code, please ignore this email.\n\nBest regards,\nThe {} Team",
            service_name, code, service_name
        );

        let email = Message::builder()
            .from(self.from.clone())
            .to(to_mailbox)
            .subject(subject)
            .body(body)
            .map_err(|e| {
                error!(to = %to, error = %e, "Failed to build email message");
                IamError::Email(e.to_string())
            })?;

        timeout(self.send_timeout, self.transport.send(email))
            .await
            .map_err(|_| {
                error!(to = %to, timeout_secs = ?self.send_timeout, "Email send timeout");
                IamError::Email(format!("Email send timeout after {} seconds", self.send_timeout.as_secs()))
            })?
            .map_err(|e: lettre::transport::smtp::Error| {
                error!(to = %to, error = %e, "Failed to send email");
                IamError::Email(e.to_string())
            })?;

        debug!(to = %to, "Verification email sent successfully");
        Ok(())
    }

    async fn send_password_reset_email(
        &self,
        to: &str,
        code: &str,
        service_name: Option<&str>,
    ) -> Result<(), IamError> {
        debug!(to = %to, "Sending password reset email");
        let to_mailbox: Mailbox = to
            .parse()
            .map_err(|e: lettre::address::AddressError| {
                error!(to = %to, error = %e, "Failed to parse email address");
                IamError::Email(e.to_string())
            })?;

        let service_name = service_name
            .or_else(|| self.service_name.as_deref())
            .unwrap_or("Our Service");
        
        let subject = format!("Reset your {} password", service_name);
        let body = format!(
            "Hello,\n\nYou requested to reset your password for {}.\n\nYour password reset code is: {}\n\nThis code will expire in a few minutes.\n\nIf you didn't request a password reset, please ignore this email and your password will remain unchanged.\n\nBest regards,\nThe {} Team",
            service_name, code, service_name
        );

        let email = Message::builder()
            .from(self.from.clone())
            .to(to_mailbox)
            .subject(subject)
            .body(body)
            .map_err(|e| {
                error!(to = %to, error = %e, "Failed to build email message");
                IamError::Email(e.to_string())
            })?;

        timeout(self.send_timeout, self.transport.send(email))
            .await
            .map_err(|_| {
                error!(to = %to, timeout_secs = ?self.send_timeout, "Email send timeout");
                IamError::Email(format!("Email send timeout after {} seconds", self.send_timeout.as_secs()))
            })?
            .map_err(|e: lettre::transport::smtp::Error| {
                error!(to = %to, error = %e, "Failed to send email");
                IamError::Email(e.to_string())
            })?;

        debug!(to = %to, "Password reset email sent successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_office365_success() {
        let config = EmailConfig {
            address: "sender@example.com".to_string(),
            username: "username".to_string(),
            password: "password".to_string(),
            server: "smtp.office365.com".to_string(),
            port: 587,
            service_name: None,
        };
        let result = LettreEmailSender::new_office365(&config);

        assert!(result.is_ok());
        let sender = result.unwrap();
        // Verify the from address was parsed correctly
        assert_eq!(sender.from.email.to_string(), "sender@example.com");
    }

    #[test]
    fn test_new_office365_invalid_email() {
        let config = EmailConfig {
            address: "not-an-email".to_string(),
            username: "username".to_string(),
            password: "password".to_string(),
            server: "smtp.office365.com".to_string(),
            port: 587,
            service_name: None,
        };
        let result = LettreEmailSender::new_office365(&config);

        assert!(result.is_err());
        match result.unwrap_err() {
            IamError::Email(_) => {}
            e => panic!("Expected IamError::Email, got {:?}", e),
        }
    }

    #[test]
    fn test_new_office365_with_different_ports() {
        // Test with different valid ports
        let ports = vec![25, 587, 465];
        
        for port in ports {
            let config = EmailConfig {
                address: "sender@example.com".to_string(),
                username: "username".to_string(),
                password: "password".to_string(),
                server: "smtp.office365.com".to_string(),
                port,
                service_name: None,
            };
            let result = LettreEmailSender::new_office365(&config);

            assert!(result.is_ok(), "Failed to create sender with port {}", port);
        }
    }

    #[test]
    fn test_new_office365_with_name_in_email() {
        // Test with email that includes a display name
        let config = EmailConfig {
            address: "Sender Name <sender@example.com>".to_string(),
            username: "username".to_string(),
            password: "password".to_string(),
            server: "smtp.office365.com".to_string(),
            port: 587,
            service_name: None,
        };
        let result = LettreEmailSender::new_office365(&config);

        assert!(result.is_ok());
        let sender = result.unwrap();
        // The email address should be extracted correctly
        assert!(sender.from.email.to_string().contains("sender@example.com"));
    }

    #[tokio::test]
    async fn test_new_office365_send_verification_email() {
        // Skip test if required environment variables are not set
        let address = match std::env::var("TEST_EMAIL_ADDRESS") {
            Ok(address) => address,
            Err(_) => {
                eprintln!("Skipping test: TEST_EMAIL_ADDRESS is not set");
                return;
            }
        };
        let username = match std::env::var("TEST_EMAIL_USERNAME") {
            Ok(username) => username,
            Err(_) => {
                eprintln!("Skipping test: TEST_EMAIL_USERNAME is not set");
                return;
            }
        };
        let password = match std::env::var("TEST_EMAIL_PASSWORD") {
            Ok(password) => password,
            Err(_) => {
                eprintln!("Skipping test: TEST_EMAIL_PASSWORD is not set");
                return;
            }
        };
        let config = EmailConfig {
            address: address.clone(),
            username: username,
            password: password,
            server: "smtp.office365.com".to_string(),
            port: 587,
            service_name: Some("Test Service".to_string()),
        };
        let sender = LettreEmailSender::new_office365(&config).expect("Failed to create sender");
        sender.send_verification_email(&address, "123456", None).await.expect("Failed to send verification email");
    }
}

