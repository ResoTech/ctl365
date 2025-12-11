use crate::config::{AuthType, ConfigManager, TenantConfig};
use crate::error::Result;
use crate::graph::auth::GraphAuth;
use crate::tui::change_tracker;
use clap::Args;
use colored::Colorize;

/// Safely truncate a string to n characters (not bytes) to prevent panics on non-ASCII
fn truncate_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Tenant/client name or abbreviation (e.g., RESO)
    /// Will check for existing config, then ~/.ctl365/{name}.env
    #[arg(index = 1)]
    name: Option<String>,

    /// Tenant name (if already configured) - alias for positional
    #[arg(short, long)]
    tenant: Option<String>,

    /// Tenant ID (Azure AD tenant ID)
    #[arg(long)]
    tenant_id: Option<String>,

    /// Client ID (Application ID)
    #[arg(long)]
    client_id: Option<String>,

    /// Client secret (for client credentials flow)
    #[arg(long)]
    client_secret: Option<String>,

    /// Use client credentials flow instead of device code
    #[arg(long)]
    client_credentials: bool,

    /// Tenant description
    #[arg(long)]
    description: Option<String>,

    /// Import from .env file only (don't authenticate)
    #[arg(long)]
    import_only: bool,
}

#[derive(Args, Debug)]
pub struct LogoutArgs {
    /// Tenant name
    #[arg(short, long)]
    tenant: Option<String>,

    /// Logout from all tenants
    #[arg(long)]
    all: bool,
}

pub async fn login(args: LoginArgs) -> Result<()> {
    let config_manager = ConfigManager::new()?;
    let auth = GraphAuth::new(config_manager.clone());

    // Resolve tenant name from positional arg or --tenant flag
    let tenant_name = args.name.as_ref().or(args.tenant.as_ref());

    let tenant_config = if let Some(name) = tenant_name {
        // Try all sources: tenants.toml, tenants.env, {name}.env
        match config_manager.get_tenant_or_env(name) {
            Ok(tenant) => {
                println!(
                    "{} Loaded tenant: {} ({})",
                    "✓".green(),
                    name.bold(),
                    tenant.description.as_deref().unwrap_or("")
                );
                println!("  Tenant ID: {}...", truncate_chars(&tenant.tenant_id, 8));
                println!("  Client ID: {}...", truncate_chars(&tenant.client_id, 8));
                if tenant.client_secret.is_some() {
                    println!("  Auth: Client Credentials");
                } else {
                    println!("  Auth: Device Code Flow");
                }

                if args.import_only {
                    println!(
                        "\n{} Import complete. Run 'ctl365 login {}' to authenticate.",
                        "→".cyan(),
                        name
                    );
                    return Ok(());
                }

                tenant
            }
            Err(_) => {
                return Err(crate::error::Ctl365Error::ConfigError(format!(
                    "Tenant '{}' not found.\n\n\
                    Options:\n\
                    1. Add to ~/.ctl365/tenants.env:\n   \
                       [{}]\n   \
                       NAME=Your Client Name\n   \
                       TENANT_ID=your-tenant-id\n   \
                       CLIENT_ID=your-client-id\n   \
                       CLIENT_SECRET=your-secret\n\n\
                    2. Create ~/.ctl365/{}.env with:\n   \
                       TENANT_ID=your-tenant-id\n   \
                       CLIENT_ID=your-client-id\n   \
                       CLIENT_SECRET=your-secret\n\n\
                    3. Use TUI: ctl365 tui dashboard -> MSP Management -> Add Client",
                    name,
                    name.to_uppercase(),
                    name.to_lowercase()
                )));
            }
        }
    } else if let (Some(tenant_id), Some(client_id)) = (&args.tenant_id, &args.client_id) {
        // Quick setup: Create new tenant config on-the-fly
        println!(
            "\n{} Quick setup mode: Creating tenant configuration...",
            "→".cyan()
        );

        let name = args.tenant.unwrap_or_else(|| {
            // Generate a friendly tenant name from tenant_id first segment
            let auto_name = tenant_id
                .split('-')
                .next()
                .unwrap_or("my-tenant")
                .to_string();
            println!(
                "\n{} Auto-generated tenant name: {}",
                "→".cyan(),
                auto_name.bold()
            );
            println!(
                "{} You can rename it later with: ctl365 tenant add <new-name> ...",
                "💡".dimmed()
            );
            auto_name
        });

        let auth_type = if args.client_credentials || args.client_secret.is_some() {
            println!(
                "{} Using client credentials flow (automation mode)",
                "🔐".cyan()
            );
            AuthType::ClientCredentials
        } else {
            println!("{} Using device code flow (interactive mode)", "🔐".cyan());
            AuthType::DeviceCode
        };

        let tenant = TenantConfig {
            name: name.clone(),
            tenant_id: tenant_id.clone(),
            client_id: client_id.clone(),
            client_secret: args.client_secret.clone(),
            auth_type,
            description: args.description,
        };

        // Save tenant config
        config_manager.add_tenant(tenant.clone())?;
        println!("{} Tenant '{}' configuration saved", "✓".green(), name);

        tenant
    } else {
        return Err(crate::error::Ctl365Error::InvalidConfig(
            "Usage:\n  \
            ctl365 login RESO           # Load from ~/.ctl365/reso.env\n  \
            ctl365 login --tenant NAME  # Use existing config\n  \
            ctl365 login --tenant-id ID --client-id ID  # Quick setup"
                .into(),
        ));
    };

    // Perform authentication
    let auth_result = match tenant_config.auth_type {
        AuthType::DeviceCode => auth.login_device_code(&tenant_config).await,
        AuthType::ClientCredentials => auth.login_client_credentials(&tenant_config).await,
    };

    match auth_result {
        Ok(_) => {
            // Record successful authentication
            change_tracker::record_auth(&tenant_config.name, true, None);

            // Set as current tenant
            let mut config = config_manager.load_config()?;
            config.current_tenant = Some(tenant_config.name.clone());
            config_manager.save_config(&config)?;

            println!(
                "\n{} Active tenant: {}",
                "→".cyan(),
                tenant_config.name.bold()
            );
            Ok(())
        }
        Err(e) => {
            // Record failed authentication
            change_tracker::record_auth(&tenant_config.name, false, Some(&e.to_string()));
            Err(e)
        }
    }
}

pub async fn logout(args: LogoutArgs) -> Result<()> {
    let config_manager = ConfigManager::new()?;
    let auth = GraphAuth::new(config_manager.clone());

    if args.all {
        // Logout from all tenants
        let tenants = config_manager.load_tenants()?;

        for tenant in &tenants {
            auth.logout(&tenant.name)?;
        }

        println!("{} Logged out from all tenants", "✓".green());
    } else if let Some(tenant_name) = &args.tenant {
        // Logout from specific tenant
        auth.logout(tenant_name)?;
    } else {
        // Logout from current tenant
        let config = config_manager.load_config()?;

        if let Some(current_tenant) = config.current_tenant {
            auth.logout(&current_tenant)?;
        } else {
            println!("{} No active tenant", "!".yellow());
        }
    }

    Ok(())
}
