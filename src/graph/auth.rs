use crate::config::{ConfigManager, TenantConfig, TokenCache};
use crate::error::{Ctl365Error, Result};
use oauth2::{
    AuthUrl, ClientId, ClientSecret, DeviceAuthorizationUrl, EmptyExtraDeviceAuthorizationFields,
    Scope, TokenResponse, TokenUrl, basic::BasicClient, reqwest::async_http_client,
};
use std::time::Duration;

const MICROSOFT_AUTHORITY: &str = "https://login.microsoftonline.com";
const GRAPH_SCOPE: &str = "https://graph.microsoft.com/.default";

/// Required Microsoft Graph API scopes (for documentation and future scope validation)
#[allow(dead_code)]
pub const REQUIRED_SCOPES: &[&str] = &[
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementApps.ReadWrite.All",
    "DeviceManagementManagedDevices.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess",
];

pub struct GraphAuth {
    config_manager: ConfigManager,
}

impl GraphAuth {
    pub fn new(config_manager: ConfigManager) -> Self {
        Self { config_manager }
    }

    /// Authenticate using device code flow (interactive)
    pub async fn login_device_code(&self, tenant_config: &TenantConfig) -> Result<TokenCache> {
        println!(
            "🔐 Starting device code authentication for tenant '{}'...",
            tenant_config.name
        );

        let tenant_id = &tenant_config.tenant_id;
        let client_id = ClientId::new(tenant_config.client_id.clone());

        let auth_url = AuthUrl::new(format!(
            "{}/{}/oauth2/v2.0/authorize",
            MICROSOFT_AUTHORITY, tenant_id
        ))
        .map_err(|e| Ctl365Error::AuthError(format!("Invalid auth URL: {}", e)))?;

        let token_url = TokenUrl::new(format!(
            "{}/{}/oauth2/v2.0/token",
            MICROSOFT_AUTHORITY, tenant_id
        ))
        .map_err(|e| Ctl365Error::AuthError(format!("Invalid token URL: {}", e)))?;

        let device_auth_url = DeviceAuthorizationUrl::new(format!(
            "{}/{}/oauth2/v2.0/devicecode",
            MICROSOFT_AUTHORITY, tenant_id
        ))
        .map_err(|e| Ctl365Error::AuthError(format!("Invalid device auth URL: {}", e)))?;

        let client = BasicClient::new(client_id, None, auth_url, Some(token_url))
            .set_device_authorization_url(device_auth_url);

        let details: oauth2::DeviceAuthorizationResponse<EmptyExtraDeviceAuthorizationFields> =
            client
                .exchange_device_code()
                .map_err(|e| Ctl365Error::AuthError(format!("Device code exchange failed: {}", e)))?
                .add_scope(Scope::new(GRAPH_SCOPE.to_string()))
                .request_async(async_http_client)
                .await
                .map_err(|e| {
                    Ctl365Error::AuthError(format!("Device authorization request failed: {}", e))
                })?;

        println!("\n📱 Please visit: {}", details.verification_uri().as_str());
        println!("🔑 Enter code: {}\n", details.user_code().secret());

        // Poll for token
        let token = client
            .exchange_device_access_token(&details)
            .request_async(async_http_client, tokio::time::sleep, None)
            .await
            .map_err(|e| Ctl365Error::AuthError(format!("Token exchange failed: {}", e)))?;

        let expires_at = chrono::Utc::now()
            + chrono::Duration::from_std(token.expires_in().unwrap_or(Duration::from_secs(3600)))
                .unwrap();

        let token_cache = TokenCache {
            access_token: token.access_token().secret().clone(),
            refresh_token: token.refresh_token().map(|t| t.secret().clone()),
            expires_at,
            tenant_id: tenant_id.clone(),
        };

        // Save token
        self.config_manager
            .save_token(&tenant_config.name, &token_cache)?;

        println!("✅ Authentication successful!");
        println!(
            "💾 Token saved to: {:?}",
            self.config_manager.token_cache_file(&tenant_config.name)
        );

        Ok(token_cache)
    }

    /// Authenticate using client credentials flow (non-interactive)
    pub async fn login_client_credentials(
        &self,
        tenant_config: &TenantConfig,
    ) -> Result<TokenCache> {
        let client_secret = tenant_config.client_secret.as_ref().ok_or_else(|| {
            Ctl365Error::AuthError("Client secret required for client credentials flow".into())
        })?;

        println!(
            "🔐 Authenticating with client credentials for tenant '{}'...",
            tenant_config.name
        );

        let tenant_id = &tenant_config.tenant_id;
        let client_id = ClientId::new(tenant_config.client_id.clone());
        let client_secret = ClientSecret::new(client_secret.clone());

        let auth_url = AuthUrl::new(format!(
            "{}/{}/oauth2/v2.0/authorize",
            MICROSOFT_AUTHORITY, tenant_id
        ))
        .map_err(|e| Ctl365Error::AuthError(format!("Invalid auth URL: {}", e)))?;

        let token_url = TokenUrl::new(format!(
            "{}/{}/oauth2/v2.0/token",
            MICROSOFT_AUTHORITY, tenant_id
        ))
        .map_err(|e| Ctl365Error::AuthError(format!("Invalid token URL: {}", e)))?;

        let client = BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url));

        let token = client
            .exchange_client_credentials()
            .add_scope(Scope::new(GRAPH_SCOPE.to_string()))
            .request_async(async_http_client)
            .await
            .map_err(|e| {
                Ctl365Error::AuthError(format!("Client credentials exchange failed: {}", e))
            })?;

        let expires_at = chrono::Utc::now()
            + chrono::Duration::from_std(token.expires_in().unwrap_or(Duration::from_secs(3600)))
                .unwrap();

        let token_cache = TokenCache {
            access_token: token.access_token().secret().clone(),
            refresh_token: None, // Client credentials don't use refresh tokens
            expires_at,
            tenant_id: tenant_id.clone(),
        };

        // Save token
        self.config_manager
            .save_token(&tenant_config.name, &token_cache)?;

        println!("✅ Authentication successful!");

        Ok(token_cache)
    }

    /// Get valid access token (loads from cache or refreshes if needed)
    pub async fn get_access_token(&self, tenant_name: &str) -> Result<String> {
        match self.config_manager.load_token(tenant_name) {
            Ok(token) => {
                // Token is valid and not expired
                Ok(token.access_token)
            }
            Err(Ctl365Error::AuthError(_)) => {
                // Token expired, need to re-authenticate
                Err(Ctl365Error::TokenNotFound)
            }
            Err(e) => Err(e),
        }
    }

    /// Logout (delete token cache)
    pub fn logout(&self, tenant_name: &str) -> Result<()> {
        self.config_manager.delete_token(tenant_name)?;
        println!("✅ Logged out from tenant '{}'", tenant_name);
        Ok(())
    }
}
