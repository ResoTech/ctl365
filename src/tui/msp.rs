//! MSP-focused client management TUI
//!
//! Provides a workflow for managing multiple client tenants with:
//! - Client abbreviations (RLAW, IRON, ITWO, etc.)
//! - App registration wizard
//! - Change tracking and reporting

use crate::config::{AuthType, ConfigManager, TenantConfig};
use crate::error::Result;
use crate::tui::prompts;
use colored::Colorize;
use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// MSP Client with friendly name and abbreviation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MspClient {
    /// Short abbreviation (e.g., RLAW, IRON, ITWO)
    pub abbreviation: String,
    /// Full client name
    pub full_name: String,
    /// Tenant ID (Azure AD)
    pub tenant_id: String,
    /// Client ID (App Registration)
    pub client_id: String,
    /// Client secret (optional, for automation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Primary contact email
    pub contact_email: Option<String>,
    /// Notes about this client
    pub notes: Option<String>,
    /// Date added
    pub added_date: String,
    /// Auth type preference
    pub auth_type: String,
}

/// MSP Configuration file
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MspConfig {
    pub msp_name: String,
    pub clients: Vec<MspClient>,
}

impl MspConfig {
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;
        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            let config: MspConfig = toml::from_str(&content).map_err(|e| {
                crate::error::Error::ConfigError(format!("Invalid MSP config: {}", e))
            })?;
            Ok(config)
        } else {
            Ok(MspConfig::default())
        }
    }

    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)
            .map_err(|e| crate::error::Error::ConfigError(format!("Failed to serialize: {}", e)))?;
        std::fs::write(&config_path, content)?;
        Ok(())
    }

    fn config_path() -> Result<PathBuf> {
        let base = directories::ProjectDirs::from("com", "ctl365", "ctl365").ok_or_else(|| {
            crate::error::Error::ConfigError("Could not find config directory".into())
        })?;
        Ok(base.config_dir().join("msp.toml"))
    }

    pub fn get_client(&self, abbreviation: &str) -> Option<&MspClient> {
        self.clients
            .iter()
            .find(|c| c.abbreviation.eq_ignore_ascii_case(abbreviation))
    }

    pub fn add_client(&mut self, client: MspClient) {
        // Remove existing if same abbreviation
        self.clients
            .retain(|c| !c.abbreviation.eq_ignore_ascii_case(&client.abbreviation));
        self.clients.push(client);
    }

    pub fn remove_client(&mut self, abbreviation: &str) -> bool {
        let len_before = self.clients.len();
        self.clients
            .retain(|c| !c.abbreviation.eq_ignore_ascii_case(abbreviation));
        self.clients.len() < len_before
    }
}

/// Main MSP client management menu
pub async fn run_msp_menu() -> Result<()> {
    let mut msp_config = MspConfig::load()?;

    // First-time setup
    if msp_config.msp_name.is_empty() {
        println!();
        println!("{}", "═".repeat(60).cyan());
        println!("{}", "  Welcome to ctl365 MSP Mode".cyan().bold());
        println!("{}", "═".repeat(60).cyan());
        println!();
        println!("  Let's set up your MSP configuration.");
        println!();

        msp_config.msp_name = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Your MSP/Company Name")
            .interact_text()?;

        msp_config.save()?;
        println!();
        prompts::success(&format!("MSP profile created: {}", msp_config.msp_name));
    }

    loop {
        println!();
        println!("{}", "═".repeat(60).cyan());
        println!(
            "  {} - {}",
            "ctl365".cyan().bold(),
            msp_config.msp_name.white().bold()
        );
        println!("{}", "═".repeat(60).cyan());

        // Show current clients summary
        if !msp_config.clients.is_empty() {
            println!();
            println!("  📋 Clients:");
            for client in &msp_config.clients {
                println!(
                    "     {} {} ({})",
                    "•".cyan(),
                    client.abbreviation.yellow().bold(),
                    client.full_name.dimmed()
                );
            }
        }
        println!();

        let menu_options = vec![
            "🏢  Add New Client",
            "📋  List Clients",
            "🔌  Switch to Client",
            "⚙️   Configure Client Settings",
            "📊  Generate Client Report",
            "🗑️   Remove Client",
            "📝  App Registration Guide",
            "🔙  Back to Main Menu",
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("What would you like to do?")
            .items(&menu_options)
            .default(0)
            .interact()?;

        match selection {
            0 => add_client_wizard(&mut msp_config).await?,
            1 => list_clients(&msp_config)?,
            2 => switch_to_client(&msp_config).await?,
            3 => configure_client(&msp_config).await?,
            4 => generate_client_report(&msp_config).await?,
            5 => remove_client(&mut msp_config)?,
            6 => show_app_registration_guide()?,
            7 => break,
            _ => {}
        }
    }

    Ok(())
}

/// Wizard to add a new client
async fn add_client_wizard(msp_config: &mut MspConfig) -> Result<()> {
    prompts::section_header("Add New Client");

    println!();
    println!("  {}", "Let's set up a new client tenant.".dimmed());
    println!(
        "  {}",
        "You'll need the Azure AD Tenant ID and an App Registration.".dimmed()
    );
    println!();

    // Abbreviation
    let abbreviation: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Client abbreviation (e.g., RLAW, IRON)")
        .validate_with(|input: &String| {
            if input.len() < 2 || input.len() > 10 {
                Err("Abbreviation should be 2-10 characters")
            } else if !input.chars().all(|c| c.is_alphanumeric()) {
                Err("Use only letters and numbers")
            } else {
                Ok(())
            }
        })
        .interact_text()?;

    // Check if already exists
    if msp_config.get_client(&abbreviation).is_some() {
        prompts::warning(&format!(
            "Client '{}' already exists. This will update it.",
            abbreviation
        ));
        if !Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Continue?")
            .default(false)
            .interact()?
        {
            return Ok(());
        }
    }

    // Full name
    let full_name: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Full client name")
        .interact_text()?;

    // Tenant ID
    println!();
    println!("  💡 Find Tenant ID in Azure Portal → Azure Active Directory → Overview");
    let tenant_id: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Azure AD Tenant ID (GUID)")
        .validate_with(|input: &String| {
            // Basic GUID validation
            if input.len() == 36 && input.matches('-').count() == 4 {
                Ok(())
            } else {
                Err("Enter a valid GUID (e.g., 12345678-1234-1234-1234-123456789abc)")
            }
        })
        .interact_text()?;

    // App Registration
    println!();
    println!("  ❓ Do you have an App Registration for this client?");

    let has_app_reg = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("App Registration already created?")
        .default(false)
        .interact()?;

    let client_id: String;
    let client_secret: Option<String>;
    let auth_type: String;

    if has_app_reg {
        client_id = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Application (Client) ID")
            .interact_text()?;

        let use_secret = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Use Client Secret for automation? (No = Device Code flow)")
            .default(false)
            .interact()?;

        if use_secret {
            client_secret = Some(
                Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Client Secret")
                    .interact_text()?,
            );
            auth_type = "ClientCredentials".to_string();
        } else {
            client_secret = None;
            auth_type = "DeviceCode".to_string();
        }
    } else {
        // Show guide and let them create one
        println!();
        prompts::info("Let's guide you through creating an App Registration.");
        show_app_registration_guide()?;

        println!();
        if !Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Have you created the App Registration?")
            .default(false)
            .interact()?
        {
            prompts::info("Come back when you've created the App Registration.");
            return Ok(());
        }

        client_id = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Application (Client) ID")
            .interact_text()?;

        client_secret = None;
        auth_type = "DeviceCode".to_string();
    }

    // Contact email (optional)
    let contact_email: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Primary contact email (optional, press Enter to skip)")
        .allow_empty(true)
        .interact_text()?;

    // Notes (optional)
    let notes: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Notes (optional)")
        .allow_empty(true)
        .interact_text()?;

    // Create the client
    let client = MspClient {
        abbreviation: abbreviation.to_uppercase(),
        full_name,
        tenant_id: tenant_id.clone(),
        client_id: client_id.clone(),
        client_secret,
        contact_email: if contact_email.is_empty() {
            None
        } else {
            Some(contact_email)
        },
        notes: if notes.is_empty() { None } else { Some(notes) },
        added_date: chrono::Utc::now().to_rfc3339(),
        auth_type: auth_type.clone(),
    };

    // Save to MSP config
    msp_config.add_client(client.clone());
    msp_config.save()?;

    // Also add to ctl365 tenant config for authentication
    let config = ConfigManager::load()?;
    let tenant_config = TenantConfig {
        name: client.abbreviation.clone(),
        tenant_id,
        client_id,
        client_secret: client.client_secret.clone(),
        auth_type: if auth_type == "ClientCredentials" {
            AuthType::ClientCredentials
        } else {
            AuthType::DeviceCode
        },
        description: Some(client.full_name.clone()),
    };
    config.add_tenant(tenant_config)?;

    println!();
    prompts::success(&format!(
        "Client '{}' ({}) added successfully!",
        client.abbreviation.yellow().bold(),
        client.full_name
    ));

    // Offer to authenticate now
    println!();
    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Authenticate to this client now?")
        .default(true)
        .interact()?
    {
        switch_to_client_by_name(&client.abbreviation).await?;
    }

    Ok(())
}

/// List all clients
fn list_clients(msp_config: &MspConfig) -> Result<()> {
    prompts::section_header("Client List");

    if msp_config.clients.is_empty() {
        println!();
        prompts::info("No clients configured yet.");
        prompts::info("Use 'Add New Client' to get started.");
        return Ok(());
    }

    println!();
    println!(
        "  {:<8} {:<30} {:<15} {}",
        "CODE".white().bold(),
        "CLIENT NAME".white().bold(),
        "AUTH TYPE".white().bold(),
        "TENANT ID".white().bold()
    );
    println!("  {}", "─".repeat(80));

    for client in &msp_config.clients {
        println!(
            "  {:<8} {:<30} {:<15} {}",
            client.abbreviation.yellow().bold(),
            truncate(&client.full_name, 28),
            client.auth_type.cyan(),
            truncate(&client.tenant_id, 20).dimmed()
        );
        if let Some(ref email) = client.contact_email {
            println!("           {} {}", "Contact:".dimmed(), email.dimmed());
        }
    }

    println!();
    println!(
        "  Total: {} clients",
        msp_config.clients.len().to_string().cyan().bold()
    );

    Ok(())
}

/// Switch to a client tenant
async fn switch_to_client(msp_config: &MspConfig) -> Result<()> {
    if msp_config.clients.is_empty() {
        prompts::warning("No clients configured. Add a client first.");
        return Ok(());
    }

    prompts::section_header("Switch Client");

    let client_names: Vec<String> = msp_config
        .clients
        .iter()
        .map(|c| format!("{} - {}", c.abbreviation.yellow(), c.full_name))
        .collect();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select client")
        .items(&client_names)
        .default(0)
        .interact()?;

    let client = &msp_config.clients[selection];
    switch_to_client_by_name(&client.abbreviation).await?;

    Ok(())
}

/// Switch to client and authenticate
async fn switch_to_client_by_name(abbreviation: &str) -> Result<()> {
    let config = ConfigManager::load()?;
    config.set_active_tenant(abbreviation)?;

    prompts::success(&format!(
        "Switched to client: {}",
        abbreviation.yellow().bold()
    ));

    // Check if we have a valid token
    let active = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("Could not load tenant".into()))?;

    prompts::info("Authenticating...");

    // Try to create graph client (this will trigger auth if needed)
    match crate::graph::GraphClient::from_config(&config, &active.name).await {
        Ok(_) => {
            prompts::success("Authentication successful!");
        }
        Err(e) => {
            prompts::error(&format!("Authentication failed: {}", e));
            prompts::info("Run 'ctl365 login' to authenticate manually.");
        }
    }

    Ok(())
}

/// Configure settings for a specific client
async fn configure_client(msp_config: &MspConfig) -> Result<()> {
    if msp_config.clients.is_empty() {
        prompts::warning("No clients configured. Add a client first.");
        return Ok(());
    }

    prompts::section_header("Configure Client");

    let client_names: Vec<String> = msp_config
        .clients
        .iter()
        .map(|c| format!("{} - {}", c.abbreviation.yellow(), c.full_name))
        .collect();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select client to configure")
        .items(&client_names)
        .default(0)
        .interact()?;

    let client = &msp_config.clients[selection];

    // Switch to client first
    switch_to_client_by_name(&client.abbreviation).await?;

    // Now show configuration menu
    let _config = ConfigManager::load()?;
    crate::tui::run_interactive_menu().await?;

    Ok(())
}

/// Generate a report for client
async fn generate_client_report(msp_config: &MspConfig) -> Result<()> {
    if msp_config.clients.is_empty() {
        prompts::warning("No clients configured. Add a client first.");
        return Ok(());
    }

    prompts::section_header("Generate Client Report");

    let client_names: Vec<String> = msp_config
        .clients
        .iter()
        .map(|c| format!("{} - {}", c.abbreviation.yellow(), c.full_name))
        .collect();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select client")
        .items(&client_names)
        .default(0)
        .interact()?;

    let client = &msp_config.clients[selection];

    // Report type
    let report_types = vec![
        "Compliance Audit Report",
        "Security Assessment",
        "Configuration Inventory",
        "Change Control Report (Session)",
        "Executive Summary",
    ];

    let report_selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Report type")
        .items(&report_types)
        .default(0)
        .interact()?;

    // Output filename
    let default_filename = format!(
        "{}-{}-report.html",
        client.abbreviation.to_lowercase(),
        chrono::Local::now().format("%Y%m%d")
    );

    let filename: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Output filename")
        .default(default_filename)
        .interact_text()?;

    prompts::info(&format!("Generating report for {}...", client.full_name));

    // Switch to client and generate
    switch_to_client_by_name(&client.abbreviation).await?;

    match report_selection {
        0 => {
            // Compliance audit
            let args = crate::cmd::audit_enhanced::ReportArgs {
                report_type: "compliance".to_string(),
                format: "html".to_string(),
                output: Some(PathBuf::from(&filename)),
                include_charts: true,
                baseline: "oib".to_string(),
            };
            crate::cmd::audit_enhanced::report(args).await?;
        }
        1 => {
            // Security assessment
            let args = crate::cmd::audit_enhanced::ReportArgs {
                report_type: "security".to_string(),
                format: "html".to_string(),
                output: Some(PathBuf::from(&filename)),
                include_charts: true,
                baseline: "oib".to_string(),
            };
            crate::cmd::audit_enhanced::report(args).await?;
        }
        2 => {
            // Inventory
            let args = crate::cmd::audit_enhanced::ReportArgs {
                report_type: "inventory".to_string(),
                format: "html".to_string(),
                output: Some(PathBuf::from(&filename)),
                include_charts: false,
                baseline: "oib".to_string(),
            };
            crate::cmd::audit_enhanced::report(args).await?;
        }
        3 => {
            // Change control - generate from session tracker
            generate_change_control_report(client, &filename)?;
        }
        4 => {
            // Executive summary
            let args = crate::cmd::audit_enhanced::ReportArgs {
                report_type: "executive".to_string(),
                format: "html".to_string(),
                output: Some(PathBuf::from(&filename)),
                include_charts: true,
                baseline: "oib".to_string(),
            };
            crate::cmd::audit_enhanced::report(args).await?;
        }
        _ => {}
    }

    println!();
    prompts::success(&format!("Report saved: {}", filename.cyan()));
    prompts::info("You can share this report with the client.");

    Ok(())
}

/// Remove a client
fn remove_client(msp_config: &mut MspConfig) -> Result<()> {
    if msp_config.clients.is_empty() {
        prompts::warning("No clients configured.");
        return Ok(());
    }

    prompts::section_header("Remove Client");

    let client_names: Vec<String> = msp_config
        .clients
        .iter()
        .map(|c| format!("{} - {}", c.abbreviation.yellow(), c.full_name))
        .collect();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select client to remove")
        .items(&client_names)
        .default(0)
        .interact()?;

    let client = &msp_config.clients[selection];
    let abbreviation = client.abbreviation.clone();
    let full_name = client.full_name.clone();

    println!();
    prompts::warning(&format!(
        "This will remove client: {} ({})",
        abbreviation, full_name
    ));

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Are you sure?")
        .default(false)
        .interact()?
    {
        msp_config.remove_client(&abbreviation);
        msp_config.save()?;

        // Also remove from ctl365 tenant config
        let config = ConfigManager::load()?;
        config.remove_tenant(&abbreviation)?;

        prompts::success(&format!("Client '{}' removed.", abbreviation));
    } else {
        prompts::info("Cancelled.");
    }

    Ok(())
}

/// Show app registration guide
fn show_app_registration_guide() -> Result<()> {
    prompts::section_header("App Registration Guide");

    println!();
    println!(
        "{}",
        "  Step-by-step guide to create an App Registration:"
            .white()
            .bold()
    );
    println!();

    println!(
        "  {}. Go to {} → portal.azure.com",
        "1".cyan().bold(),
        "Azure Portal".yellow()
    );

    println!(
        "  {}. Navigate to {} → App registrations",
        "2".cyan().bold(),
        "Azure Active Directory".yellow()
    );

    println!(
        "  {}. Click {}",
        "3".cyan().bold(),
        "New registration".green().bold()
    );

    println!("  {}. Enter app details:", "4".cyan().bold());
    println!("       Name: {}", "ctl365-msp-management".yellow());
    println!(
        "       Supported account types: {}",
        "Single tenant".yellow()
    );
    println!(
        "       Redirect URI: {}",
        "https://login.microsoftonline.com/common/oauth2/nativeclient".dimmed()
    );

    println!(
        "  {}. Click {} and note the:",
        "5".cyan().bold(),
        "Register".green()
    );
    println!("       • {} (Client ID)", "Application ID".yellow().bold());
    println!("       • {} (Tenant ID)", "Directory ID".yellow().bold());

    println!(
        "  {}. Go to {} and add:",
        "6".cyan().bold(),
        "API Permissions".yellow()
    );

    println!();
    println!(
        "  {}",
        "Required Microsoft Graph Permissions:".white().bold()
    );
    println!("  {}", "─".repeat(50));

    let permissions = vec![
        (
            "DeviceManagementConfiguration.ReadWrite.All",
            "Intune policies",
        ),
        (
            "DeviceManagementManagedDevices.ReadWrite.All",
            "Device management",
        ),
        ("Policy.ReadWrite.ConditionalAccess", "CA policies"),
        ("Directory.Read.All", "User/group info"),
        ("Organization.Read.All", "Tenant info"),
        ("SecurityEvents.Read.All", "Security data"),
        ("Mail.Read", "Exchange Online (optional)"),
    ];

    for (perm, desc) in permissions {
        println!("    {} {} - {}", "•".cyan(), perm.yellow(), desc.dimmed());
    }

    println!();
    println!(
        "  {}. Click {} after adding permissions",
        "7".cyan().bold(),
        "Grant admin consent".green().bold()
    );

    println!();
    println!(
        "  {}. (Optional) Create a {} for automation:",
        "8".cyan().bold(),
        "Client Secret".yellow()
    );
    println!(
        "       Go to {} → {} → set expiry",
        "Certificates & secrets".yellow(),
        "New client secret".green()
    );

    println!();
    prompts::info("Press Enter when ready to continue...");
    let mut _input = String::new();
    std::io::stdin().read_line(&mut _input)?;

    Ok(())
}

/// Generate change control HTML report
fn generate_change_control_report(client: &MspClient, filename: &str) -> Result<()> {
    // Load session changes
    let changes = crate::tui::change_tracker::load_session_changes()?;

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Change Control Report - {}</title>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 40px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .header {{
            border-bottom: 3px solid #0078d4;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #0078d4;
            margin: 0 0 10px 0;
        }}
        .client-info {{
            background: #f3f2f1;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 30px;
        }}
        .client-info p {{
            margin: 5px 0;
        }}
        .changes {{
            margin-top: 30px;
        }}
        .change {{
            border-left: 4px solid #0078d4;
            padding: 15px;
            margin: 15px 0;
            background: #fafafa;
            border-radius: 0 4px 4px 0;
        }}
        .change.created {{ border-left-color: #107c10; }}
        .change.modified {{ border-left-color: #f7b500; }}
        .change.deleted {{ border-left-color: #d13438; }}
        .change-header {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }}
        .change-type {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }}
        .change-type.created {{ background: #dff6dd; color: #107c10; }}
        .change-type.modified {{ background: #fff4ce; color: #8a6914; }}
        .change-type.deleted {{ background: #fde7e9; color: #d13438; }}
        .timestamp {{
            color: #605e5c;
            font-size: 12px;
        }}
        .setting-name {{
            font-weight: bold;
            color: #323130;
        }}
        .values {{
            margin-top: 10px;
            font-family: monospace;
            font-size: 13px;
        }}
        .old-value {{ color: #d13438; }}
        .new-value {{ color: #107c10; }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #edebe9;
            color: #605e5c;
            font-size: 12px;
            text-align: center;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin: 30px 0;
        }}
        .summary-card {{
            background: #f3f2f1;
            padding: 20px;
            border-radius: 4px;
            text-align: center;
        }}
        .summary-card .number {{
            font-size: 36px;
            font-weight: bold;
            color: #0078d4;
        }}
        .summary-card .label {{
            font-size: 12px;
            color: #605e5c;
            text-transform: uppercase;
        }}
        .no-changes {{
            text-align: center;
            padding: 40px;
            color: #605e5c;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Change Control Report</h1>
            <p>Microsoft 365 Configuration Changes</p>
        </div>

        <div class="client-info">
            <p><strong>Client:</strong> {} ({})</p>
            <p><strong>Tenant ID:</strong> {}</p>
            <p><strong>Report Date:</strong> {}</p>
            <p><strong>Generated By:</strong> ctl365</p>
        </div>

        <div class="summary">
            <div class="summary-card">
                <div class="number">{}</div>
                <div class="label">Total Changes</div>
            </div>
            <div class="summary-card">
                <div class="number" style="color: #107c10;">{}</div>
                <div class="label">Created</div>
            </div>
            <div class="summary-card">
                <div class="number" style="color: #f7b500;">{}</div>
                <div class="label">Modified</div>
            </div>
        </div>

        <h2>Changes</h2>
        <div class="changes">
            {}
        </div>

        <div class="footer">
            <p>Generated by ctl365 v{} on {}</p>
            <p>This report documents configuration changes made to the Microsoft 365 tenant.</p>
        </div>
    </div>
</body>
</html>"#,
        client.full_name,
        client.full_name,
        client.abbreviation,
        client.tenant_id,
        chrono::Local::now().format("%Y-%m-%d %H:%M"),
        changes.len(),
        changes
            .iter()
            .filter(|c| c.change_type == "created")
            .count(),
        changes
            .iter()
            .filter(|c| c.change_type == "modified")
            .count(),
        if changes.is_empty() {
            "<div class='no-changes'>No changes recorded in this session.</div>".to_string()
        } else {
            changes
                .iter()
                .map(|change| {
                    format!(
                        r#"<div class="change {}">
                    <div class="change-header">
                        <span class="change-type {}">{}</span>
                        <span class="timestamp">{}</span>
                    </div>
                    <div class="setting-name">{}</div>
                    <div class="values">
                        {}
                        {}
                    </div>
                </div>"#,
                        change.change_type,
                        change.change_type,
                        change.change_type.to_uppercase(),
                        change.timestamp,
                        change.setting_name,
                        change
                            .old_value
                            .as_ref()
                            .map(|v| format!("<div class='old-value'>- {}</div>", v))
                            .unwrap_or_default(),
                        change
                            .new_value
                            .as_ref()
                            .map(|v| format!("<div class='new-value'>+ {}</div>", v))
                            .unwrap_or_default(),
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        },
        env!("CARGO_PKG_VERSION"),
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
    );

    std::fs::write(filename, html)?;
    Ok(())
}

/// Truncate string with ellipsis
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}
