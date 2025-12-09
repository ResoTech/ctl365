use crate::config::{AuthType, ConfigManager, TenantConfig};
use crate::error::Result;
use clap::Args;
use colored::Colorize;

#[derive(Args, Debug)]
pub struct TenantAddArgs {
    /// Tenant name
    name: String,

    /// Tenant ID (Azure AD tenant ID)
    #[arg(long)]
    tenant_id: String,

    /// Client ID (Application ID)
    #[arg(long)]
    client_id: String,

    /// Client secret (for client credentials flow)
    #[arg(long)]
    client_secret: Option<String>,

    /// Use client credentials flow
    #[arg(long)]
    client_credentials: bool,

    /// Tenant description
    #[arg(long)]
    description: Option<String>,
}

#[derive(Args, Debug)]
pub struct TenantListArgs {
    /// Show detailed information
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Args, Debug)]
pub struct TenantSwitchArgs {
    /// Tenant name to switch to
    name: String,
}

#[derive(Args, Debug)]
pub struct TenantRemoveArgs {
    /// Tenant name to remove
    name: String,
}

pub async fn add(args: TenantAddArgs) -> Result<()> {
    let config_manager = ConfigManager::new()?;

    let auth_type = if args.client_credentials {
        AuthType::ClientCredentials
    } else {
        AuthType::DeviceCode
    };

    let tenant = TenantConfig {
        name: args.name.clone(),
        tenant_id: args.tenant_id,
        client_id: args.client_id,
        client_secret: args.client_secret,
        auth_type,
        description: args.description,
    };

    config_manager.add_tenant(tenant)?;

    println!("{} Tenant '{}' added successfully", "✓".green(), args.name);
    println!(
        "\n{} Run {} to authenticate",
        "→".cyan(),
        format!("ctl365 login --tenant {}", args.name).bold()
    );

    Ok(())
}

pub async fn list(args: TenantListArgs) -> Result<()> {
    let config_manager = ConfigManager::new()?;
    let tenants = config_manager.load_tenants()?;
    let config = config_manager.load_config()?;

    if tenants.is_empty() {
        println!("{} No tenants configured", "!".yellow());
        println!(
            "\n{} Run {} to add a tenant",
            "→".cyan(),
            "ctl365 tenant add".bold()
        );
        return Ok(());
    }

    println!("\n{}", "Configured Tenants:".bold());
    println!("{}", "─".repeat(60));

    for tenant in &tenants {
        let is_current = config.current_tenant.as_ref() == Some(&tenant.name);
        let marker = if is_current {
            "●".green()
        } else {
            "○".dimmed()
        };

        println!("\n{} {}", marker, tenant.name.bold());

        if args.verbose {
            println!("  Tenant ID:    {}", tenant.tenant_id);
            println!("  Client ID:    {}", tenant.client_id);
            println!("  Auth Type:    {:?}", tenant.auth_type);

            if let Some(desc) = &tenant.description {
                println!("  Description:  {}", desc);
            }

            // Check if authenticated
            match config_manager.load_token(&tenant.name) {
                Ok(token) => {
                    println!(
                        "  Status:       {} (expires: {})",
                        "Authenticated".green(),
                        token.expires_at.format("%Y-%m-%d %H:%M:%S UTC")
                    );
                }
                Err(_) => {
                    println!("  Status:       {}", "Not authenticated".yellow());
                }
            }
        }
    }

    println!("\n{}", "─".repeat(60));
    println!("{} {} tenant(s) total", "→".cyan(), tenants.len());

    if let Some(current) = &config.current_tenant {
        println!("{} Active: {}", "→".cyan(), current.bold());
    }

    Ok(())
}

pub async fn switch(args: TenantSwitchArgs) -> Result<()> {
    let config_manager = ConfigManager::new()?;

    // Verify tenant exists
    let _tenant = config_manager.get_tenant(&args.name)?;

    // Set as current
    let mut config = config_manager.load_config()?;
    config.current_tenant = Some(args.name.clone());
    config_manager.save_config(&config)?;

    println!("{} Switched to tenant '{}'", "✓".green(), args.name);

    Ok(())
}

pub async fn remove(args: TenantRemoveArgs) -> Result<()> {
    let config_manager = ConfigManager::new()?;

    let mut tenants = config_manager.load_tenants()?;
    let original_len = tenants.len();

    tenants.retain(|t| t.name != args.name);

    if tenants.len() == original_len {
        return Err(crate::error::Ctl365Error::TenantNotFound(args.name));
    }

    config_manager.save_tenants(&tenants)?;

    // Delete token if exists
    let _ = config_manager.delete_token(&args.name);

    // Update current tenant if it was the removed one
    let mut config = config_manager.load_config()?;
    if config.current_tenant.as_ref() == Some(&args.name) {
        config.current_tenant = None;
        config_manager.save_config(&config)?;
    }

    println!("{} Tenant '{}' removed", "✓".green(), args.name);

    Ok(())
}
