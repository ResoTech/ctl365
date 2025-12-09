use thiserror::Error;

#[derive(Error, Debug)]
pub enum Ctl365Error {
    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Graph API error: {0}")]
    GraphApiError(String),

    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerdeError(#[from] serde_json::Error),

    #[error("TOML parsing error: {0}")]
    TomlError(#[from] toml::de::Error),

    #[error("ZIP error: {0}")]
    ZipError(#[from] zip::result::ZipError),

    #[error("Directory walk error: {0}")]
    WalkDirError(#[from] walkdir::Error),

    #[error("Interactive prompt error: {0}")]
    DialoguerError(#[from] dialoguer::Error),

    #[error("Token not found. Please run 'ctl365 login' first")]
    TokenNotFound,

    #[error("Tenant '{0}' not found")]
    TenantNotFound(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

pub type Result<T> = std::result::Result<T, Ctl365Error>;

// Alias for backward compatibility
pub use Ctl365Error as Error;

/// Parse Graph API error response and provide helpful context
pub fn enhance_graph_error(error_response: &str) -> String {
    // Try to parse as JSON to extract error details
    if let Ok(error_json) = serde_json::from_str::<serde_json::Value>(error_response) {
        if let Some(error_obj) = error_json.get("error") {
            let code = error_obj
                .get("code")
                .and_then(|c| c.as_str())
                .unwrap_or("Unknown");
            let message = error_obj
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("No message");

            // Provide helpful context for common errors
            let hint = match code {
                "Unauthorized" | "InvalidAuthenticationToken" => {
                    "\n💡 Hint: Your authentication token may have expired. Try running 'ctl365 login' again."
                }
                "Forbidden" | "InsufficientPrivileges" => {
                    "\n💡 Hint: Check that your app registration has the required permissions and admin consent is granted."
                }
                "BadRequest" => {
                    if message.contains("Resource not found for the segment") {
                        "\n💡 Hint: This API endpoint may require the beta endpoint or different permissions."
                    } else if message.contains("already exists") {
                        "\n💡 Hint: A policy with this name already exists. Use a different name or delete the existing policy."
                    } else {
                        "\n💡 Hint: The request format may be incorrect. Check the policy structure."
                    }
                }
                "NotFound" => {
                    "\n💡 Hint: The requested resource doesn't exist. Check IDs and resource names."
                }
                "TooManyRequests" => {
                    "\n💡 Hint: API rate limit exceeded. Wait a moment and try again."
                }
                _ => "",
            };

            return format!("{}: {}{}", code, message, hint);
        }
    }

    // If we can't parse it, return the raw error
    error_response.to_string()
}
