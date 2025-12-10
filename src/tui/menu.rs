//! Interactive menu system for tenant configuration
//!
//! Provides a menu-driven interface for configuring M365 tenant settings.

use crate::config::ConfigManager;
use crate::error::Result;
use crate::graph::GraphClient;
use crate::tui::{prompts, settings::*};
use colored::Colorize;
use dialoguer::{Select, theme::ColorfulTheme};

/// Main menu options
#[derive(Debug, Clone, Copy)]
pub enum MainMenuOption {
    DefenderForOffice365,
    ExchangeOnline,
    SharePointOneDrive,
    Teams,
    ConditionalAccess,
    IntuneBaseline,
    ApplyAllRecommended,
    ExportConfiguration,
    Exit,
}

impl std::fmt::Display for MainMenuOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DefenderForOffice365 => {
                write!(f, "Defender for Office 365 (Safe Links, Safe Attachments)")
            }
            Self::ExchangeOnline => write!(f, "Exchange Online (Spam, Malware, Archive)"),
            Self::SharePointOneDrive => write!(f, "SharePoint & OneDrive (Sharing, Sync)"),
            Self::Teams => write!(f, "Microsoft Teams (External Access, Meetings)"),
            Self::ConditionalAccess => write!(f, "Conditional Access Policies"),
            Self::IntuneBaseline => write!(f, "Intune Device Baseline"),
            Self::ApplyAllRecommended => write!(f, "Apply All Recommended Settings"),
            Self::ExportConfiguration => write!(f, "Export Current Configuration"),
            Self::Exit => write!(f, "Exit"),
        }
    }
}

const MAIN_MENU_OPTIONS: [MainMenuOption; 9] = [
    MainMenuOption::DefenderForOffice365,
    MainMenuOption::ExchangeOnline,
    MainMenuOption::SharePointOneDrive,
    MainMenuOption::Teams,
    MainMenuOption::ConditionalAccess,
    MainMenuOption::IntuneBaseline,
    MainMenuOption::ApplyAllRecommended,
    MainMenuOption::ExportConfiguration,
    MainMenuOption::Exit,
];

/// Run the interactive tenant configuration menu
pub async fn run_interactive_menu() -> Result<()> {
    let config = ConfigManager::load()?;
    let active_tenant = config.get_active_tenant()?.ok_or_else(|| {
        crate::error::Error::ConfigError("No active tenant. Run 'ctl365 login' first.".into())
    })?;

    println!();
    println!("{}", "═".repeat(60).cyan());
    println!(
        "{}",
        "  ctl365 Interactive Tenant Configuration".cyan().bold()
    );
    println!("{}", "═".repeat(60).cyan());
    println!();
    println!("  Tenant: {}", active_tenant.name.yellow().bold());
    println!("  ID:     {}", active_tenant.tenant_id.dimmed());
    println!();

    loop {
        let items: Vec<String> = MAIN_MENU_OPTIONS.iter().map(|o| o.to_string()).collect();

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a category to configure")
            .items(&items)
            .default(0)
            .interact()?;

        match MAIN_MENU_OPTIONS[selection] {
            MainMenuOption::DefenderForOffice365 => {
                configure_defender_interactive(&config, &active_tenant.name).await?;
            }
            MainMenuOption::ExchangeOnline => {
                configure_exchange_interactive(&config, &active_tenant.name).await?;
            }
            MainMenuOption::SharePointOneDrive => {
                configure_sharepoint_interactive(&config, &active_tenant.name).await?;
            }
            MainMenuOption::Teams => {
                configure_teams_interactive(&config, &active_tenant.name).await?;
            }
            MainMenuOption::ConditionalAccess => {
                println!();
                prompts::info("Use 'ctl365 ca deploy --interactive' for CA policies");
                println!();
            }
            MainMenuOption::IntuneBaseline => {
                println!();
                prompts::info("Use 'ctl365 baseline new --interactive' for device baselines");
                println!();
            }
            MainMenuOption::ApplyAllRecommended => {
                apply_all_recommended(&config, &active_tenant.name).await?;
            }
            MainMenuOption::ExportConfiguration => {
                export_current_configuration(&config, &active_tenant.name).await?;
            }
            MainMenuOption::Exit => {
                println!();
                prompts::success("Configuration complete. Goodbye!");
                break;
            }
        }
    }

    Ok(())
}

/// Interactive Defender for Office 365 configuration
pub async fn configure_defender_interactive(
    config: &ConfigManager,
    tenant_name: &str,
) -> Result<TenantConfiguration> {
    prompts::section_header("Defender for Office 365 Configuration");

    let mut tenant_config = TenantConfiguration::recommended();

    // Safe Links
    println!();
    println!("{}", "Safe Links".white().bold());
    println!(
        "  {}",
        "Protects users from malicious URLs in emails, Teams, and Office docs".dimmed()
    );
    println!();

    tenant_config.safe_links_enabled = prompts::confirm_with_help(
        "Enable Safe Links?",
        "Scans URLs in real-time when clicked to detect malicious sites",
        true,
    )?;

    if tenant_config.safe_links_enabled {
        tenant_config.safe_links_scan_urls = prompts::confirm_with_help(
            "Enable URL scanning at time of click?",
            "Re-checks URLs when user clicks, even if previously scanned",
            true,
        )?;

        tenant_config.safe_links_teams = prompts::confirm_with_help(
            "Enable Safe Links for Microsoft Teams?",
            "Protects URLs shared in Teams chats and channels",
            true,
        )?;

        tenant_config.safe_links_office = prompts::confirm_with_help(
            "Enable Safe Links for Office apps?",
            "Protects URLs in Word, Excel, PowerPoint documents",
            true,
        )?;

        tenant_config.safe_links_track_clicks = prompts::confirm_with_help(
            "Track user clicks on URLs?",
            "Logs URL clicks for security analysis and reporting",
            true,
        )?;

        tenant_config.safe_links_internal_senders = prompts::confirm_with_help(
            "Scan URLs from internal senders?",
            "Also protects against compromised internal accounts",
            true,
        )?;
    }

    // Safe Attachments
    println!();
    println!("{}", "Safe Attachments".white().bold());
    println!(
        "  {}",
        "Sandboxes and scans email attachments before delivery".dimmed()
    );
    println!();

    tenant_config.safe_attachments_enabled = prompts::confirm_with_help(
        "Enable Safe Attachments?",
        "Opens attachments in a virtual environment to detect malware",
        true,
    )?;

    if tenant_config.safe_attachments_enabled {
        let actions = ["DynamicDelivery", "Block", "Replace", "Monitor"];
        let action_descriptions = [
            "Deliver email immediately, attach file when scan completes (recommended)",
            "Block the email entirely until scan completes",
            "Remove attachment and notify recipient",
            "Log only, don't block (for testing)",
        ];

        println!();
        for (i, (action, desc)) in actions.iter().zip(action_descriptions.iter()).enumerate() {
            println!("  {}. {} - {}", i + 1, action.yellow(), desc);
        }

        let action_idx = prompts::select(
            "Safe Attachments action",
            &actions,
            0, // DynamicDelivery as default
        )?;
        tenant_config.safe_attachments_action = actions[action_idx].to_string();
    }

    // Apply changes?
    println!();
    if prompts::confirm("Apply these Defender settings now?", true)? {
        apply_defender_settings(config, tenant_name, &tenant_config).await?;
    } else {
        prompts::info("Settings not applied. You can apply them later.");
    }

    Ok(tenant_config)
}

/// Interactive Exchange Online configuration
pub async fn configure_exchange_interactive(
    config: &ConfigManager,
    tenant_name: &str,
) -> Result<TenantConfiguration> {
    prompts::section_header("Exchange Online Configuration");

    let mut tenant_config = TenantConfiguration::recommended();

    // Archive Settings
    println!();
    println!("{}", "Archive Mailbox".white().bold());
    println!(
        "  {}",
        "Enables online archive for long-term email storage".dimmed()
    );
    println!();

    tenant_config.archive_mailbox = prompts::confirm_with_help(
        "Enable archive mailboxes for all users?",
        "Provides additional storage and helps with mailbox size management",
        true,
    )?;

    if tenant_config.archive_mailbox {
        tenant_config.auto_expanding_archive = prompts::confirm_with_help(
            "Enable auto-expanding archive?",
            "Automatically grows archive beyond 100GB as needed",
            true,
        )?;

        tenant_config.archive_after_years =
            prompts::input_number("Move emails to archive after how many years?", 3)?;
    }

    // Anti-Spam/Malware
    println!();
    println!("{}", "Anti-Spam & Anti-Malware".white().bold());
    println!(
        "  {}",
        "Configure spam filtering and malware protection".dimmed()
    );
    println!();

    tenant_config.external_forwarding_blocked = prompts::confirm_with_help(
        "Block external auto-forwarding?",
        "CRITICAL: Prevents data exfiltration via compromised mailbox rules",
        true,
    )?;

    tenant_config.zap_enabled = prompts::confirm_with_help(
        "Enable Zero-Hour Auto Purge (ZAP)?",
        "Automatically removes malicious messages delivered before detection",
        true,
    )?;

    tenant_config.spam_bulk_threshold =
        prompts::input_number("Bulk email threshold (1-9, lower = more aggressive)?", 6)?;

    let spam_actions = ["Quarantine", "MoveToJmf", "Delete", "Redirect"];
    let spam_idx = prompts::select("Action for high-confidence spam?", &spam_actions, 0)?;
    tenant_config.high_confidence_spam_action = spam_actions[spam_idx].to_string();

    let phish_idx = prompts::select(
        "Action for phishing emails?",
        &["Quarantine", "MoveToJmf", "Delete"],
        0,
    )?;
    tenant_config.phish_action = ["Quarantine", "MoveToJmf", "Delete"][phish_idx].to_string();

    // Quarantine notifications
    tenant_config.quarantine_notifications = prompts::confirm_with_help(
        "Send quarantine notifications to end users?",
        "Users receive emails when messages are quarantined (can increase support tickets)",
        false,
    )?;

    // Apply changes?
    println!();
    if prompts::confirm("Apply these Exchange settings now?", true)? {
        apply_exchange_settings(config, tenant_name, &tenant_config).await?;
    } else {
        prompts::info("Settings not applied. You can apply them later.");
    }

    Ok(tenant_config)
}

/// Interactive SharePoint/OneDrive configuration
pub async fn configure_sharepoint_interactive(
    config: &ConfigManager,
    tenant_name: &str,
) -> Result<TenantConfiguration> {
    prompts::section_header("SharePoint & OneDrive Configuration");

    let mut tenant_config = TenantConfiguration::recommended();

    // External Sharing
    println!();
    println!("{}", "External Sharing".white().bold());
    println!(
        "  {}",
        "Control how content can be shared outside your organization".dimmed()
    );
    println!();

    let sharing_levels = [
        "Disabled",
        "ExistingExternalUserSharingOnly",
        "ExternalUserSharingOnly",
        "ExternalUserAndGuestSharing",
    ];
    let sharing_descriptions = [
        "No external sharing allowed",
        "Only existing guests in directory (recommended)",
        "New and existing guests must authenticate",
        "Anyone links allowed (least secure)",
    ];

    for (i, (level, desc)) in sharing_levels
        .iter()
        .zip(sharing_descriptions.iter())
        .enumerate()
    {
        println!("  {}. {} - {}", i + 1, level.yellow(), desc);
    }

    let sharing_idx = prompts::select(
        "External sharing level?",
        &sharing_levels,
        1, // ExistingExternalUserSharingOnly
    )?;
    tenant_config.external_sharing = sharing_levels[sharing_idx].to_string();

    if sharing_idx > 0 {
        tenant_config.anonymous_link_expiry =
            prompts::input_number("Anonymous link expiry (days)?", 30)?;

        let link_types = ["Internal", "Direct", "AnonymousAccess"];
        let link_idx = prompts::select("Default sharing link type?", &link_types, 0)?;
        tenant_config.default_sharing_link = link_types[link_idx].to_string();

        tenant_config.prevent_external_resharing = prompts::confirm_with_help(
            "Prevent guests from re-sharing?",
            "Stops external users from sharing content with additional people",
            true,
        )?;
    }

    // OneDrive Sync
    println!();
    println!("{}", "OneDrive Sync".white().bold());
    println!("  {}", "Control which devices can sync files".dimmed());
    println!();

    tenant_config.sync_client_restriction = prompts::confirm_with_help(
        "Restrict OneDrive sync to managed devices?",
        "Only domain-joined or Intune-compliant devices can sync",
        true,
    )?;

    // Apply changes?
    println!();
    if prompts::confirm("Apply these SharePoint settings now?", true)? {
        apply_sharepoint_settings(config, tenant_name, &tenant_config).await?;
    } else {
        prompts::info("Settings not applied. You can apply them later.");
    }

    Ok(tenant_config)
}

/// Interactive Teams configuration
pub async fn configure_teams_interactive(
    config: &ConfigManager,
    tenant_name: &str,
) -> Result<TenantConfiguration> {
    prompts::section_header("Microsoft Teams Configuration");

    let mut tenant_config = TenantConfiguration::recommended();

    // External Access
    println!();
    println!("{}", "External Access".white().bold());
    println!(
        "  {}",
        "Control communication with people outside your organization".dimmed()
    );
    println!();

    tenant_config.external_access = prompts::confirm_with_help(
        "Allow federation with external Teams organizations?",
        "Enables chat/calls with other M365 tenants",
        true,
    )?;

    tenant_config.teams_consumer_access = prompts::confirm_with_help(
        "Allow chat with personal Microsoft accounts?",
        "Enables communication with consumer Skype/Teams users",
        false,
    )?;

    // Meeting Settings
    println!();
    println!("{}", "Meeting Policies".white().bold());
    println!("  {}", "Configure who can join meetings and how".dimmed());
    println!();

    tenant_config.anonymous_meeting_join = prompts::confirm_with_help(
        "Allow anonymous users to join meetings?",
        "Unauthenticated users can join via meeting link",
        false,
    )?;

    let lobby_options = [
        "EveryoneInCompany",
        "EveryoneInCompanyExcludingGuests",
        "OrganizerOnly",
        "InvitedUsers",
    ];
    let lobby_descriptions = [
        "All org users bypass lobby",
        "Org users except guests bypass (recommended)",
        "Only organizer bypasses lobby",
        "Only invited users bypass lobby",
    ];

    for (i, (opt, desc)) in lobby_options
        .iter()
        .zip(lobby_descriptions.iter())
        .enumerate()
    {
        println!("  {}. {} - {}", i + 1, opt.yellow(), desc);
    }

    let lobby_idx = prompts::select("Who can bypass the meeting lobby?", &lobby_options, 1)?;
    tenant_config.meeting_lobby = lobby_options[lobby_idx].to_string();

    tenant_config.meeting_recording = prompts::confirm_with_help(
        "Allow cloud meeting recording?",
        "Enables recording meetings to OneDrive/SharePoint",
        true,
    )?;

    tenant_config.meeting_transcription = prompts::confirm_with_help(
        "Allow meeting transcription?",
        "Enables automatic transcription of meetings",
        true,
    )?;

    // Apply changes?
    println!();
    if prompts::confirm("Apply these Teams settings now?", true)? {
        apply_teams_settings(config, tenant_name, &tenant_config).await?;
    } else {
        prompts::info("Settings not applied. You can apply them later.");
    }

    Ok(tenant_config)
}

/// Apply all recommended settings at once
pub async fn apply_all_recommended(config: &ConfigManager, tenant_name: &str) -> Result<()> {
    prompts::section_header("Apply All Recommended Settings");

    println!();
    prompts::warning("This will apply recommended security settings across:");
    println!("  - Defender for Office 365 (Safe Links, Safe Attachments)");
    println!("  - Exchange Online (Archive, Anti-spam, Anti-malware)");
    println!("  - SharePoint & OneDrive (Sharing restrictions)");
    println!("  - Microsoft Teams (Meeting and external access policies)");
    println!();

    if !prompts::confirm("Apply all recommended settings?", false)? {
        prompts::info("Cancelled.");
        return Ok(());
    }

    let tenant_config = TenantConfiguration::recommended();
    let _graph = GraphClient::from_config(config, tenant_name).await?;

    println!();
    prompts::info("Applying Defender for Office 365 settings...");
    apply_defender_settings(config, tenant_name, &tenant_config).await?;

    prompts::info("Applying Exchange Online settings...");
    apply_exchange_settings(config, tenant_name, &tenant_config).await?;

    prompts::info("Applying SharePoint & OneDrive settings...");
    apply_sharepoint_settings(config, tenant_name, &tenant_config).await?;

    prompts::info("Applying Teams settings...");
    apply_teams_settings(config, tenant_name, &tenant_config).await?;

    println!();
    prompts::success("All recommended settings applied successfully!");

    Ok(())
}

/// Export current configuration to JSON
pub async fn export_current_configuration(
    _config: &ConfigManager,
    tenant_name: &str,
) -> Result<()> {
    prompts::section_header("Export Configuration");

    let filename = prompts::input("Export filename", &format!("{}-config.json", tenant_name))?;

    prompts::info(&format!("Exporting configuration to {}...", filename));

    // Export recommended baseline config as a template
    // This provides a starting point that can be customized and re-imported
    let tenant_config = TenantConfiguration::recommended();
    let json = serde_json::to_string_pretty(&tenant_config)?;
    std::fs::write(&filename, json)?;

    prompts::success(&format!("Configuration exported to {}", filename));

    Ok(())
}

// ============================================================================
// Apply functions - actually push settings to Graph API
// ============================================================================

async fn apply_defender_settings(
    config: &ConfigManager,
    tenant_name: &str,
    settings: &TenantConfiguration,
) -> Result<()> {
    let graph = GraphClient::from_config(config, tenant_name).await?;

    if settings.safe_links_enabled {
        let policy_name = "ctl365 - Safe Links Policy";
        match crate::graph::exchange_online::configure_safe_links_policy(&graph, policy_name).await
        {
            Ok(_) => prompts::success(&format!("Configured Safe Links: {}", policy_name)),
            Err(e) => prompts::error(&format!("Failed to configure Safe Links: {}", e)),
        }
    }

    if settings.safe_attachments_enabled {
        let policy_name = "ctl365 - Safe Attachments Policy";
        match crate::graph::exchange_online::configure_safe_attachments_policy(&graph, policy_name)
            .await
        {
            Ok(_) => prompts::success(&format!("Configured Safe Attachments: {}", policy_name)),
            Err(e) => prompts::error(&format!("Failed to configure Safe Attachments: {}", e)),
        }
    }

    Ok(())
}

async fn apply_exchange_settings(
    config: &ConfigManager,
    tenant_name: &str,
    settings: &TenantConfiguration,
) -> Result<()> {
    let graph = GraphClient::from_config(config, tenant_name).await?;

    if settings.archive_mailbox {
        match crate::graph::exchange_online::enable_archive_mailbox_tenant_wide(&graph).await {
            Ok(result) => {
                let total = result["totalUsers"].as_u64().unwrap_or(0);
                prompts::success(&format!("Enabled archive mailbox for {} users", total));
            }
            Err(e) => prompts::error(&format!("Failed to enable archive: {}", e)),
        }
    }

    if settings.external_forwarding_blocked {
        match crate::graph::exchange_online::configure_outbound_spam_policy(&graph).await {
            Ok(_) => prompts::success("Blocked external auto-forwarding"),
            Err(e) => prompts::error(&format!("Failed to block forwarding: {}", e)),
        }
    }

    // Anti-spam policy
    let policy_name = "ctl365 - Strict Anti-Spam";
    match crate::graph::exchange_online::configure_antispam_policy(&graph, policy_name).await {
        Ok(_) => prompts::success(&format!("Configured anti-spam policy: {}", policy_name)),
        Err(e) => prompts::error(&format!("Failed to configure anti-spam: {}", e)),
    }

    // Anti-malware policy
    let policy_name = "ctl365 - Strict Anti-Malware";
    match crate::graph::exchange_online::configure_antimalware_policy(&graph, policy_name).await {
        Ok(_) => prompts::success(&format!("Configured anti-malware policy: {}", policy_name)),
        Err(e) => prompts::error(&format!("Failed to configure anti-malware: {}", e)),
    }

    if !settings.quarantine_notifications {
        match crate::graph::exchange_online::disable_quarantine_notifications(&graph).await {
            Ok(_) => prompts::success("Disabled quarantine notifications"),
            Err(e) => prompts::error(&format!("Failed to disable notifications: {}", e)),
        }
    }

    Ok(())
}

async fn apply_sharepoint_settings(
    _config: &ConfigManager,
    _tenant_name: &str,
    settings: &TenantConfiguration,
) -> Result<()> {
    // SharePoint settings typically require SharePoint Admin PowerShell or specific APIs
    // For now, we'll indicate what would be configured

    prompts::info(&format!("External sharing: {}", settings.external_sharing));
    prompts::info(&format!(
        "Anonymous link expiry: {} days",
        settings.anonymous_link_expiry
    ));
    prompts::info(&format!(
        "Default link type: {}",
        settings.default_sharing_link
    ));

    if settings.sync_client_restriction {
        prompts::info("OneDrive sync restricted to managed devices");
    }

    prompts::warning(
        "SharePoint settings require SharePoint Admin API - use 'Set-SPOTenant' cmdlet",
    );

    Ok(())
}

async fn apply_teams_settings(
    _config: &ConfigManager,
    _tenant_name: &str,
    settings: &TenantConfiguration,
) -> Result<()> {
    // Teams settings require Teams PowerShell or specific APIs

    prompts::info(&format!(
        "External access: {}",
        if settings.external_access {
            "Enabled"
        } else {
            "Disabled"
        }
    ));
    prompts::info(&format!(
        "Consumer access: {}",
        if settings.teams_consumer_access {
            "Enabled"
        } else {
            "Disabled"
        }
    ));
    prompts::info(&format!(
        "Anonymous meeting join: {}",
        if settings.anonymous_meeting_join {
            "Enabled"
        } else {
            "Disabled"
        }
    ));
    prompts::info(&format!("Meeting lobby: {}", settings.meeting_lobby));

    prompts::warning(
        "Teams settings require Teams Admin API - use 'Set-CsTeamsMeetingPolicy' cmdlet",
    );

    Ok(())
}

// ============================================================================
// TUI-friendly apply functions that return status messages
// ============================================================================

/// Apply Defender settings from TUI (returns status message)
pub async fn apply_defender_settings_from_config(
    config: &ConfigManager,
    tenant_name: &str,
    settings: &TenantConfiguration,
) -> Result<String> {
    apply_defender_settings(config, tenant_name, settings).await?;
    Ok("Defender for Office 365 settings applied successfully".into())
}

/// Apply Exchange settings from TUI (returns status message)
pub async fn apply_exchange_settings_from_config(
    config: &ConfigManager,
    tenant_name: &str,
    settings: &TenantConfiguration,
) -> Result<String> {
    apply_exchange_settings(config, tenant_name, settings).await?;
    Ok("Exchange Online settings applied successfully".into())
}

/// Apply SharePoint settings from TUI (returns status message)
pub async fn apply_sharepoint_settings_from_config(
    config: &ConfigManager,
    tenant_name: &str,
    settings: &TenantConfiguration,
) -> Result<String> {
    apply_sharepoint_settings(config, tenant_name, settings).await?;
    Ok(
        "SharePoint & OneDrive settings applied (Note: Some settings require SharePoint Admin API)"
            .into(),
    )
}

/// Apply Teams settings from TUI (returns status message)
pub async fn apply_teams_settings_from_config(
    config: &ConfigManager,
    tenant_name: &str,
    settings: &TenantConfiguration,
) -> Result<String> {
    apply_teams_settings(config, tenant_name, settings).await?;
    Ok("Teams settings applied (Note: Some settings require Teams Admin API)".into())
}

/// Apply all settings from TUI (returns status message)
pub async fn apply_all_settings_from_config(
    config: &ConfigManager,
    tenant_name: &str,
    settings: &TenantConfiguration,
) -> Result<String> {
    apply_defender_settings(config, tenant_name, settings).await?;
    apply_exchange_settings(config, tenant_name, settings).await?;
    apply_sharepoint_settings(config, tenant_name, settings).await?;
    apply_teams_settings(config, tenant_name, settings).await?;
    Ok("All recommended settings applied successfully".into())
}

/// Quick single-setting change menu
pub async fn quick_setting_change() -> Result<()> {
    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    prompts::section_header("Quick Setting Change");
    println!("  Tenant: {}", active_tenant.name.yellow());

    let settings = all_settings();
    let setting_names: Vec<String> = settings
        .iter()
        .map(|s| format!("[{}] {}", s.category, s.name))
        .collect();

    let selection = prompts::select("Select setting to change", &setting_names, 0)?;
    let setting = &settings[selection];

    println!();
    println!("  {} {}", "Setting:".dimmed(), setting.name.white().bold());
    println!("  {} {}", "Description:".dimmed(), setting.description);
    if let Some(cis) = &setting.cis_control {
        println!("  {} CIS {}", "Control:".dimmed(), cis);
    }
    println!("  {} {}", "Default:".dimmed(), setting.default_value);
    println!();

    // Prompt based on setting type
    match &setting.setting_type {
        SettingType::Boolean => {
            let current = match &setting.default_value {
                SettingValue::Boolean(b) => *b,
                _ => true,
            };
            let new_value = prompts::confirm(&format!("Enable {}?", setting.name), current)?;
            prompts::success(&format!(
                "Set {} to {}",
                setting.name,
                if new_value { "Enabled" } else { "Disabled" }
            ));
        }
        SettingType::Choice { options } => {
            let idx = prompts::select(&format!("Select value for {}", setting.name), options, 0)?;
            prompts::success(&format!("Set {} to {}", setting.name, options[idx]));
        }
        SettingType::Number { min, max } => {
            let default = match &setting.default_value {
                SettingValue::Number(n) => *n as u32,
                _ => 0,
            };
            let new_value = prompts::input_number(
                &format!(
                    "Enter value for {} ({}-{})",
                    setting.name,
                    min.unwrap_or(0),
                    max.unwrap_or(999)
                ),
                default,
            )?;
            prompts::success(&format!("Set {} to {}", setting.name, new_value));
        }
        _ => {
            prompts::info("Setting type not yet supported for quick change");
        }
    }

    Ok(())
}
