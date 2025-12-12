use crate::error::{Ctl365Error, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

// ============================================================================
// Client Configuration (Individual TOML files per client)
// ============================================================================

/// Client configuration stored in ~/.ctl365/clients/{abbrev}.toml
///
/// Example file structure:
/// ```toml
/// [client]
/// name = "Resolve Technology"
/// abbreviation = "RESO"
/// contact_email = "admin@resolvetech.com"
/// notes = "Primary MSP tenant"
///
/// [azure]
/// tenant_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
/// app_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
/// client_secret = "your-secret-here"  # Optional
///
/// [branding]
/// logo_path = ""
/// primary_color = "#0078D4"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub client: ClientInfo,
    pub azure: AzureCredentials,
    #[serde(default)]
    pub branding: ClientBranding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub abbreviation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub added_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureCredentials {
    pub tenant_id: String,
    pub app_id: String,
    /// Optional - if set, enables Client Credentials flow (no sign-in needed)
    /// If empty/missing, uses Device Code flow (interactive)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientBranding {
    #[serde(default)]
    pub logo_path: String,
    #[serde(default = "default_primary_color")]
    pub primary_color: String,
}

fn default_primary_color() -> String {
    "#0078D4".to_string()
}

impl ClientConfig {
    /// Get the base config directory (~/.ctl365)
    pub fn base_dir() -> Result<PathBuf> {
        let home = dirs_next::home_dir()
            .ok_or_else(|| Ctl365Error::ConfigError("Could not determine home directory".into()))?;
        Ok(home.join(".ctl365"))
    }

    /// Get the clients directory (~/.ctl365/clients)
    pub fn clients_dir() -> Result<PathBuf> {
        Ok(Self::base_dir()?.join("clients"))
    }

    /// Get the reports directory (~/.ctl365/reports)
    pub fn reports_dir() -> Result<PathBuf> {
        Ok(Self::base_dir()?.join("reports"))
    }

    /// Get the client-specific reports directory (~/.ctl365/reports/{abbrev})
    pub fn client_reports_dir(abbreviation: &str) -> Result<PathBuf> {
        let abbrev = abbreviation.to_lowercase();
        Ok(Self::reports_dir()?.join(abbrev))
    }

    /// Get path for a specific client config file
    pub fn client_file(abbreviation: &str) -> Result<PathBuf> {
        let abbrev = abbreviation.to_lowercase();
        Ok(Self::clients_dir()?.join(format!("{}.toml", abbrev)))
    }

    /// Load a client config from file
    pub fn load(abbreviation: &str) -> Result<Self> {
        let path = Self::client_file(abbreviation)?;
        if !path.exists() {
            return Err(Ctl365Error::TenantNotFound(abbreviation.to_string()));
        }
        let content = fs::read_to_string(&path)?;
        let config: ClientConfig = toml::from_str(&content)
            .map_err(|e| Ctl365Error::ConfigError(format!("Invalid client config: {}", e)))?;
        Ok(config)
    }

    /// Save client config to file
    pub fn save(&self) -> Result<()> {
        let clients_dir = Self::clients_dir()?;
        if !clients_dir.exists() {
            fs::create_dir_all(&clients_dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o700);
                std::fs::set_permissions(&clients_dir, perms)?;
            }
        }

        let path = Self::client_file(&self.client.abbreviation)?;
        let content = toml::to_string_pretty(self)
            .map_err(|e| Ctl365Error::ConfigError(format!("Failed to serialize config: {}", e)))?;
        fs::write(&path, &content)?;

        // Set restrictive permissions on the file (contains secrets)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perms)?;
        }

        Ok(())
    }

    /// Delete a client config file
    pub fn delete(abbreviation: &str) -> Result<()> {
        let path = Self::client_file(abbreviation)?;
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// List all client abbreviations
    pub fn list_clients() -> Result<Vec<String>> {
        let clients_dir = Self::clients_dir()?;
        if !clients_dir.exists() {
            return Ok(Vec::new());
        }

        let mut clients = Vec::new();
        for entry in fs::read_dir(&clients_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "toml") {
                if let Some(stem) = path.file_stem() {
                    clients.push(stem.to_string_lossy().to_uppercase());
                }
            }
        }
        clients.sort();
        Ok(clients)
    }

    /// Load all client configs
    pub fn load_all() -> Result<Vec<ClientConfig>> {
        let abbreviations = Self::list_clients()?;
        let mut configs = Vec::new();
        for abbrev in abbreviations {
            match Self::load(&abbrev) {
                Ok(config) => configs.push(config),
                Err(e) => {
                    eprintln!("Warning: Failed to load client {}: {}", abbrev, e);
                }
            }
        }
        Ok(configs)
    }

    /// Check if client secret is configured (enables unattended auth)
    pub fn has_client_secret(&self) -> bool {
        self.azure
            .client_secret
            .as_ref()
            .is_some_and(|s| !s.is_empty())
    }

    /// Get the auth type based on whether client_secret is set
    pub fn auth_type(&self) -> AuthType {
        if self.has_client_secret() {
            AuthType::ClientCredentials
        } else {
            AuthType::DeviceCode
        }
    }

    /// Convert to TenantConfig for authentication
    pub fn to_tenant_config(&self) -> TenantConfig {
        TenantConfig {
            name: self.client.abbreviation.clone(),
            tenant_id: self.azure.tenant_id.clone(),
            client_id: self.azure.app_id.clone(),
            client_secret: self.azure.client_secret.clone(),
            auth_type: self.auth_type(),
            description: Some(self.client.name.clone()),
        }
    }

    /// Create from existing TenantConfig (migration helper)
    pub fn from_tenant_config(tenant: &TenantConfig) -> Self {
        ClientConfig {
            client: ClientInfo {
                name: tenant
                    .description
                    .clone()
                    .unwrap_or_else(|| tenant.name.clone()),
                abbreviation: tenant.name.clone(),
                contact_email: None,
                notes: None,
                added_date: Some(chrono::Utc::now().to_rfc3339()),
            },
            azure: AzureCredentials {
                tenant_id: tenant.tenant_id.clone(),
                app_id: tenant.client_id.clone(),
                client_secret: tenant.client_secret.clone(),
            },
            branding: ClientBranding::default(),
        }
    }

    /// Ensure base directories exist
    pub fn ensure_directories() -> Result<()> {
        let base = Self::base_dir()?;
        let clients = Self::clients_dir()?;
        let reports = Self::reports_dir()?;

        for dir in [&base, &clients, &reports] {
            if !dir.exists() {
                fs::create_dir_all(dir)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o700);
                    std::fs::set_permissions(dir, perms)?;
                }
            }
        }
        Ok(())
    }

    /// Generate a sample/template config file
    pub fn generate_template(abbreviation: &str) -> String {
        format!(
            r##"# Client Configuration for {abbrev}
# This file contains Azure credentials - keep it secure!

[client]
name = "Client Full Name"
abbreviation = "{abbrev}"
contact_email = "admin@example.com"
notes = "Optional notes about this client"

[azure]
tenant_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
app_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
# Optional: Set client_secret for unattended authentication
# If omitted, Device Code flow (interactive sign-in) will be used
# client_secret = "your-secret-here"

[branding]
logo_path = ""
primary_color = "#0078D4"
"##,
            abbrev = abbreviation.to_uppercase()
        )
    }
}

// ============================================================================
// Legacy Configuration (kept for backward compatibility)
// ============================================================================

/// Sanitize a tenant name for use in filenames and identifiers
///
/// Rules:
/// - Converts to lowercase
/// - Replaces spaces with hyphens
/// - Removes characters invalid for Windows/Unix filenames: <>:"/\|?*
/// - Removes control characters
/// - Collapses multiple hyphens to single
/// - Trims leading/trailing hyphens and whitespace
/// - Returns None if result would be empty
pub fn sanitize_tenant_name(name: &str) -> Option<String> {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_whitespace() || c.is_ascii_control() || "<>:\"/\\|?*".contains(c) {
                '-'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();

    // Collapse multiple hyphens and trim
    let mut result = String::new();
    let mut prev_hyphen = false;
    for c in sanitized.chars() {
        if c == '-' {
            if !prev_hyphen && !result.is_empty() {
                result.push(c);
            }
            prev_hyphen = true;
        } else {
            result.push(c);
            prev_hyphen = false;
        }
    }

    // Trim trailing hyphen
    let result = result.trim_end_matches('-').to_string();

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Validate a tenant name
///
/// Returns Ok if valid, Err with message if invalid
pub fn validate_tenant_name(name: &str) -> std::result::Result<(), String> {
    if name.is_empty() {
        return Err("Tenant name cannot be empty".to_string());
    }

    if name.len() > 64 {
        return Err("Tenant name cannot exceed 64 characters".to_string());
    }

    // Check for invalid characters
    let invalid_chars: Vec<char> = name
        .chars()
        .filter(|c| c.is_ascii_control() || "<>:\"/\\|?*".contains(*c))
        .collect();

    if !invalid_chars.is_empty() {
        return Err(format!(
            "Tenant name contains invalid characters: {:?}",
            invalid_chars
        ));
    }

    // Check it doesn't start or end with space/hyphen
    if name.starts_with(' ') || name.starts_with('-') {
        return Err("Tenant name cannot start with space or hyphen".to_string());
    }

    if name.ends_with(' ') || name.ends_with('-') {
        return Err("Tenant name cannot end with space or hyphen".to_string());
    }

    Ok(())
}

/// Set restrictive permissions (0o600) on a file (Unix only)
#[cfg(unix)]
fn set_restricted_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)
}

/// No-op on non-Unix platforms
#[cfg(not(unix))]
fn set_restricted_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// Set restrictive permissions (0o700) on a directory (Unix only)
#[cfg(unix)]
fn set_restricted_dir_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(path, perms)
}

/// No-op on non-Unix platforms
#[cfg(not(unix))]
fn set_restricted_dir_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// Main configuration structure
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub default_tenant: Option<String>,

    #[serde(default)]
    pub log_level: String,

    #[serde(default)]
    pub current_tenant: Option<String>,
}

/// Tenant-specific configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TenantConfig {
    pub name: String,
    pub tenant_id: String,
    pub client_id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,

    #[serde(default)]
    pub auth_type: AuthType,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    #[default]
    DeviceCode,
    ClientCredentials,
}

/// Token cache structure
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenCache {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub tenant_id: String,
}

/// Configuration manager
#[derive(Clone)]
pub struct ConfigManager {
    config_dir: PathBuf,
}

impl Default for ConfigManager {
    /// Create a ConfigManager with a fallback config directory.
    /// This is used when normal initialization fails (e.g., in tests or restricted environments).
    fn default() -> Self {
        // Try standard location first, fall back to temp directory
        let config_dir = directories::ProjectDirs::from("com", "ctl365", "ctl365")
            .map(|pd| pd.config_dir().to_path_buf())
            .unwrap_or_else(|| std::env::temp_dir().join("ctl365"));

        Self { config_dir }
    }
}

impl ConfigManager {
    pub fn new() -> Result<Self> {
        let project_dirs = ProjectDirs::from("com", "ctl365", "ctl365").ok_or_else(|| {
            Ctl365Error::ConfigError("Failed to determine config directory".into())
        })?;

        let config_dir = project_dirs.config_dir().to_path_buf();

        // Create config directory if it doesn't exist
        if !config_dir.exists() {
            fs::create_dir_all(&config_dir)?;
            // Set config directory to 0o700 (owner only) - contains sensitive credentials
            set_restricted_dir_permissions(&config_dir)?;
        }

        Ok(Self { config_dir })
    }

    /// Alias for new() to match usage in baseline.rs
    pub fn load() -> Result<Self> {
        Self::new()
    }

    #[allow(dead_code)]
    pub fn config_dir(&self) -> &PathBuf {
        &self.config_dir
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    pub fn tenants_file(&self) -> PathBuf {
        self.config_dir.join("tenants.toml")
    }

    pub fn token_cache_file(&self, tenant_name: &str) -> PathBuf {
        self.config_dir
            .join("cache")
            .join(format!("{}.token", tenant_name))
    }

    /// Load main config
    pub fn load_config(&self) -> Result<Config> {
        let config_path = self.config_file();

        if !config_path.exists() {
            return Ok(Config::default());
        }

        let contents = fs::read_to_string(config_path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Save main config
    pub fn save_config(&self, config: &Config) -> Result<()> {
        let config_path = self.config_file();
        let contents = toml::to_string_pretty(config)
            .map_err(|e| Ctl365Error::ConfigError(format!("Failed to serialize config: {}", e)))?;
        fs::write(config_path, contents)?;
        Ok(())
    }

    /// Load all tenants
    pub fn load_tenants(&self) -> Result<Vec<TenantConfig>> {
        let tenants_path = self.tenants_file();

        if !tenants_path.exists() {
            return Ok(Vec::new());
        }

        let contents = fs::read_to_string(tenants_path)?;

        #[derive(Deserialize)]
        struct TenantsFile {
            tenants: Vec<TenantConfig>,
        }

        let file: TenantsFile = toml::from_str(&contents)?;
        Ok(file.tenants)
    }

    /// Save all tenants with restrictive permissions (0o600 on Unix)
    /// Note: tenants.toml may contain client secrets
    pub fn save_tenants(&self, tenants: &[TenantConfig]) -> Result<()> {
        let tenants_path = self.tenants_file();

        #[derive(Serialize)]
        struct TenantsFile<'a> {
            tenants: &'a [TenantConfig],
        }

        let file = TenantsFile { tenants };
        let contents = toml::to_string_pretty(&file)
            .map_err(|e| Ctl365Error::ConfigError(format!("Failed to serialize tenants: {}", e)))?;
        fs::write(&tenants_path, contents)?;

        // Set tenants file to 0o600 (owner read/write only) - contains client secrets
        set_restricted_permissions(&tenants_path)?;

        Ok(())
    }

    /// Add or update tenant
    ///
    /// Validates tenant name before adding
    pub fn add_tenant(&self, tenant: TenantConfig) -> Result<()> {
        // Validate tenant name
        if let Err(msg) = validate_tenant_name(&tenant.name) {
            return Err(Ctl365Error::ConfigError(msg));
        }

        let mut tenants = self.load_tenants()?;

        // Remove existing tenant with same name
        tenants.retain(|t| t.name != tenant.name);

        tenants.push(tenant);
        self.save_tenants(&tenants)?;
        Ok(())
    }

    /// Get tenant by name
    pub fn get_tenant(&self, name: &str) -> Result<TenantConfig> {
        let tenants = self.load_tenants()?;
        tenants
            .into_iter()
            .find(|t| t.name == name)
            .ok_or_else(|| Ctl365Error::TenantNotFound(name.to_string()))
    }

    /// Get active tenant
    pub fn get_active_tenant(&self) -> Result<Option<TenantConfig>> {
        let config = self.load_config()?;

        match config.current_tenant {
            Some(tenant_name) => Ok(Some(self.get_tenant(&tenant_name)?)),
            None => Ok(None),
        }
    }

    /// Save token cache with restrictive permissions (0o600 on Unix)
    pub fn save_token(&self, tenant_name: &str, token: &TokenCache) -> Result<()> {
        let cache_dir = self.config_dir.join("cache");
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir)?;
            // Set cache directory to 0o700 (owner only)
            set_restricted_dir_permissions(&cache_dir)?;
        }

        let token_path = self.token_cache_file(tenant_name);
        let contents = serde_json::to_string_pretty(token)?;
        fs::write(&token_path, contents)?;

        // Set token file to 0o600 (owner read/write only) - prevents credential exposure
        set_restricted_permissions(&token_path)?;

        Ok(())
    }

    /// Load token cache
    pub fn load_token(&self, tenant_name: &str) -> Result<TokenCache> {
        let token_path = self.token_cache_file(tenant_name);

        if !token_path.exists() {
            return Err(Ctl365Error::TokenNotFound);
        }

        let contents = fs::read_to_string(token_path)?;
        let token: TokenCache = serde_json::from_str(&contents)?;

        // Check if token is expired
        if token.expires_at < chrono::Utc::now() {
            return Err(Ctl365Error::AuthError("Token expired".into()));
        }

        Ok(token)
    }

    /// Delete token cache
    pub fn delete_token(&self, tenant_name: &str) -> Result<()> {
        let token_path = self.token_cache_file(tenant_name);

        if token_path.exists() {
            fs::remove_file(token_path)?;
        }

        Ok(())
    }

    /// Set the active tenant
    pub fn set_active_tenant(&self, tenant_name: &str) -> Result<()> {
        // Verify tenant exists
        let _tenant = self.get_tenant(tenant_name)?;

        // Update config
        let mut config = self.load_config()?;
        config.current_tenant = Some(tenant_name.to_string());
        self.save_config(&config)?;

        Ok(())
    }

    /// Remove a tenant by name
    pub fn remove_tenant(&self, tenant_name: &str) -> Result<()> {
        let mut tenants = self.load_tenants()?;
        let original_len = tenants.len();
        tenants.retain(|t| !t.name.eq_ignore_ascii_case(tenant_name));

        if tenants.len() == original_len {
            return Err(Ctl365Error::TenantNotFound(tenant_name.to_string()));
        }

        self.save_tenants(&tenants)?;

        // Also delete token cache
        let _ = self.delete_token(tenant_name);

        // If this was the active tenant, clear current_tenant
        let config = self.load_config()?;
        if config.current_tenant.as_deref() == Some(tenant_name) {
            let mut updated_config = config;
            updated_config.current_tenant = None;
            self.save_config(&updated_config)?;
        }

        Ok(())
    }

    /// List all tenant names
    pub fn list_tenant_names(&self) -> Result<Vec<String>> {
        let tenants = self.load_tenants()?;
        Ok(tenants.into_iter().map(|t| t.name).collect())
    }

    /// Load tenant from .env file in config directory
    ///
    /// Supports format:
    /// ```
    /// # Client: RESO - Resolve M365 Baseline
    /// TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    /// CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    /// CLIENT_SECRET=your-secret-here
    /// ```
    pub fn load_env_file(&self, name: &str) -> Result<Option<TenantConfig>> {
        // Check for .env file: ~/.ctl365/{name}.env or ~/.ctl365/.env
        let env_path = self.config_dir.join(format!("{}.env", name.to_lowercase()));
        let fallback_path = self.config_dir.join(".env");

        let path = if env_path.exists() {
            env_path
        } else if fallback_path.exists() {
            fallback_path
        } else {
            return Ok(None);
        };

        let contents = fs::read_to_string(&path)?;
        let env_vars = Self::parse_env_file(&contents);

        let tenant_id = env_vars
            .get("TENANT_ID")
            .or_else(|| env_vars.get("tenant_id"));
        let client_id = env_vars
            .get("CLIENT_ID")
            .or_else(|| env_vars.get("client_id"));
        let client_secret = env_vars
            .get("CLIENT_SECRET")
            .or_else(|| env_vars.get("client_secret"));

        match (tenant_id, client_id) {
            (Some(tid), Some(cid)) => Ok(Some(TenantConfig {
                name: name.to_string(),
                tenant_id: tid.clone(),
                client_id: cid.clone(),
                client_secret: client_secret.cloned(),
                auth_type: if client_secret.is_some() {
                    AuthType::ClientCredentials
                } else {
                    AuthType::DeviceCode
                },
                description: env_vars
                    .get("DESCRIPTION")
                    .or_else(|| env_vars.get("description"))
                    .cloned(),
            })),
            _ => Ok(None),
        }
    }

    /// Parse simple .env file format
    fn parse_env_file(contents: &str) -> HashMap<String, String> {
        let mut vars = HashMap::new();

        for line in contents.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse KEY=VALUE
            if let Some(pos) = line.find('=') {
                let key = line[..pos].trim().to_string();
                let value = line[pos + 1..].trim();

                // Remove surrounding quotes if present
                let value = if (value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\''))
                {
                    value[1..value.len() - 1].to_string()
                } else {
                    value.to_string()
                };

                vars.insert(key, value);
            }
        }

        vars
    }

    /// Import tenant from .env file and save to tenants.toml
    pub fn import_from_env(&self, name: &str) -> Result<TenantConfig> {
        match self.load_env_file(name)? {
            Some(tenant) => {
                self.add_tenant(tenant.clone())?;
                Ok(tenant)
            }
            None => Err(Ctl365Error::ConfigError(format!(
                "No .env file found. Create ~/.ctl365/{}.env with:\nTENANT_ID=xxx\nCLIENT_ID=xxx\nCLIENT_SECRET=xxx",
                name.to_lowercase()
            ))),
        }
    }

    /// Load all tenants from a multi-tenant .env file
    ///
    /// Format:
    /// ```
    /// # ~/.ctl365/tenants.env
    /// [RESO]
    /// NAME=Resolve Technology
    /// TENANT_ID=c59151ed-4414-4426-b239-08974ab0e805
    /// CLIENT_ID=3c54f805-db0a-4f83-be24-6744ab9fd758
    /// CLIENT_SECRET=D9h8Q~xxx
    ///
    /// [ACME]
    /// NAME=Acme Corporation
    /// TENANT_ID=xxx
    /// CLIENT_ID=xxx
    /// CLIENT_SECRET=xxx
    /// ```
    pub fn load_tenants_env(&self) -> Result<Vec<TenantConfig>> {
        let env_path = self.config_dir.join("tenants.env");

        if !env_path.exists() {
            return Ok(Vec::new());
        }

        let contents = fs::read_to_string(&env_path)?;
        let mut tenants = Vec::new();
        let mut current_section: Option<String> = None;
        let mut current_vars: HashMap<String, String> = HashMap::new();

        for line in contents.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Check for section header [ABBREV]
            if line.starts_with('[') && line.ends_with(']') {
                // Save previous section
                if let Some(abbrev) = current_section.take() {
                    if let Some(tenant) = Self::vars_to_tenant(&abbrev, &current_vars) {
                        tenants.push(tenant);
                    }
                }

                current_section = Some(line[1..line.len() - 1].to_string());
                current_vars.clear();
                continue;
            }

            // Parse KEY=VALUE
            if let Some(pos) = line.find('=') {
                let key = line[..pos].trim().to_uppercase();
                let value = line[pos + 1..].trim();

                // Remove quotes
                let value = if (value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\''))
                {
                    value[1..value.len() - 1].to_string()
                } else {
                    value.to_string()
                };

                current_vars.insert(key, value);
            }
        }

        // Don't forget the last section
        if let Some(abbrev) = current_section {
            if let Some(tenant) = Self::vars_to_tenant(&abbrev, &current_vars) {
                tenants.push(tenant);
            }
        }

        Ok(tenants)
    }

    fn vars_to_tenant(abbrev: &str, vars: &HashMap<String, String>) -> Option<TenantConfig> {
        let tenant_id = vars.get("TENANT_ID")?;
        let client_id = vars.get("CLIENT_ID")?;
        let client_secret = vars.get("CLIENT_SECRET");
        let name = vars
            .get("NAME")
            .cloned()
            .unwrap_or_else(|| abbrev.to_string());

        Some(TenantConfig {
            name: abbrev.to_uppercase(),
            tenant_id: tenant_id.clone(),
            client_id: client_id.clone(),
            client_secret: client_secret.cloned(),
            auth_type: if client_secret.is_some() {
                AuthType::ClientCredentials
            } else {
                AuthType::DeviceCode
            },
            description: Some(name),
        })
    }

    /// Import all tenants from tenants.env and merge into tenants.toml
    pub fn import_all_from_env(&self) -> Result<usize> {
        let env_tenants = self.load_tenants_env()?;
        let count = env_tenants.len();

        for tenant in env_tenants {
            self.add_tenant(tenant)?;
        }

        Ok(count)
    }

    /// Get tenant by name, checking all config sources
    ///
    /// Search order:
    /// 1. tenants.toml (legacy format)
    /// 2. ~/.ctl365/clients/{name}.toml (new TUI format)
    /// 3. tenants.env (multi-tenant env file)
    /// 4. {name}.env (individual env file)
    pub fn get_tenant_or_env(&self, name: &str) -> Result<TenantConfig> {
        // First check tenants.toml (case-insensitive)
        if let Ok(tenants) = self.load_tenants() {
            if let Some(tenant) = tenants
                .into_iter()
                .find(|t| t.name.eq_ignore_ascii_case(name))
            {
                return Ok(tenant);
            }
        }

        // Check new client config format (~/.ctl365/clients/{name}.toml)
        if let Ok(client_config) = ClientConfig::load(name) {
            // Convert ClientConfig to TenantConfig
            let auth_type = if client_config.has_client_secret() {
                AuthType::ClientCredentials
            } else {
                AuthType::DeviceCode
            };
            let tenant = TenantConfig {
                name: client_config.client.abbreviation.clone(),
                tenant_id: client_config.azure.tenant_id,
                client_id: client_config.azure.app_id,
                client_secret: client_config.azure.client_secret,
                description: Some(client_config.client.name),
                auth_type,
            };
            return Ok(tenant);
        }

        // Check multi-tenant env file
        let env_tenants = self.load_tenants_env()?;
        if let Some(tenant) = env_tenants
            .into_iter()
            .find(|t| t.name.eq_ignore_ascii_case(name))
        {
            // Save to tenants.toml for future use
            self.add_tenant(tenant.clone())?;
            return Ok(tenant);
        }

        // Check individual env file
        if let Some(tenant) = self.load_env_file(name)? {
            self.add_tenant(tenant.clone())?;
            return Ok(tenant);
        }

        Err(Ctl365Error::TenantNotFound(name.to_string()))
    }
}
