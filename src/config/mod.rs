use crate::error::{Ctl365Error, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

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

impl ConfigManager {
    pub fn new() -> Result<Self> {
        let project_dirs = ProjectDirs::from("com", "ctl365", "ctl365").ok_or_else(|| {
            Ctl365Error::ConfigError("Failed to determine config directory".into())
        })?;

        let config_dir = project_dirs.config_dir().to_path_buf();

        // Create config directory if it doesn't exist
        if !config_dir.exists() {
            fs::create_dir_all(&config_dir)?;
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

    /// Save all tenants
    pub fn save_tenants(&self, tenants: &[TenantConfig]) -> Result<()> {
        let tenants_path = self.tenants_file();

        #[derive(Serialize)]
        struct TenantsFile<'a> {
            tenants: &'a [TenantConfig],
        }

        let file = TenantsFile { tenants };
        let contents = toml::to_string_pretty(&file)
            .map_err(|e| Ctl365Error::ConfigError(format!("Failed to serialize tenants: {}", e)))?;
        fs::write(tenants_path, contents)?;
        Ok(())
    }

    /// Add or update tenant
    pub fn add_tenant(&self, tenant: TenantConfig) -> Result<()> {
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

    /// Save token cache
    pub fn save_token(&self, tenant_name: &str, token: &TokenCache) -> Result<()> {
        let cache_dir = self.config_dir.join("cache");
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir)?;
        }

        let token_path = self.token_cache_file(tenant_name);
        let contents = serde_json::to_string_pretty(token)?;
        fs::write(token_path, contents)?;
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

    /// Get tenant by name, checking env files first
    pub fn get_tenant_or_env(&self, name: &str) -> Result<TenantConfig> {
        // First check tenants.toml
        if let Ok(tenant) = self.get_tenant(name) {
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
