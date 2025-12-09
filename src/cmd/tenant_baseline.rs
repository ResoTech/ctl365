/// Tenant-wide Microsoft 365 baseline deployment
///
/// Configures organization-level settings for Exchange Online, SharePoint, Teams, etc.
use crate::config::ConfigManager;
use crate::error::Result;
use crate::graph::{GraphClient, exchange_online};
use clap::Args;
use colored::Colorize;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct ConfigureArgs {
    /// Configuration name/prefix
    #[arg(short, long, default_value = "Production")]
    pub name: String,

    /// Enable archive mailbox for all users
    #[arg(long)]
    pub enable_archive: bool,

    /// Years before moving emails to archive (default: 3)
    #[arg(long, default_value = "3")]
    pub archive_after_years: u32,

    /// Disable quarantine email notifications to end users
    #[arg(long)]
    pub disable_quarantine_alerts: bool,

    /// Configure anti-spam policies
    #[arg(long)]
    pub configure_spam_filter: bool,

    /// Configure all recommended tenant settings
    #[arg(long)]
    pub all: bool,

    /// Enable Defender for Office 365 features (Safe Links, Safe Attachments)
    #[arg(long)]
    pub defender_office: bool,

    /// Generate baseline file without applying
    #[arg(long, short)]
    pub output: Option<PathBuf>,

    /// Dry run - show what would be configured
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(short, long)]
    pub yes: bool,

    /// Interactive mode - configure each setting with y/n prompts
    #[arg(short, long)]
    pub interactive: bool,
}

pub async fn configure(args: ConfigureArgs) -> Result<()> {
    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    // If interactive mode, launch the TUI
    if args.interactive {
        return crate::tui::run_interactive_menu().await;
    }

    println!("{} tenant-wide baseline...", "Configuring".cyan().bold());
    println!("→ Tenant: {}", active_tenant.name.cyan().bold());

    // If output file specified, generate baseline JSON and save
    if let Some(output_path) = &args.output {
        println!("→ Generating baseline configuration...");

        let baseline_args = crate::cmd::baseline::NewArgs {
            platform: "tenant".to_string(),
            name: args.name.clone(),
            template: "baseline".to_string(),
            encryption: false,
            defender: args.defender_office,
            min_os: None,
            mde_onboarding: None,
            output: Some(output_path.clone()),
        };

        let baseline = crate::templates::tenant_baseline::generate_tenant_baseline(&baseline_args)?;

        std::fs::write(output_path, serde_json::to_string_pretty(&baseline)?)?;
        println!(
            "{} Baseline saved to: {}",
            "✓".green().bold(),
            output_path.display()
        );
        return Ok(());
    }

    // Apply tenant configurations
    if !args.yes && !args.dry_run {
        use std::io::{self, Write};
        print!(
            "\n{} Configure tenant-wide settings for '{}'? This will affect all users. [y/N]: ",
            "?".yellow().bold(),
            active_tenant.name
        );
        io::stdout().flush()?;

        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        if !response.trim().eq_ignore_ascii_case("y") {
            println!("{}", "Cancelled.".yellow());
            return Ok(());
        }
    }

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;
    let mut configured_count = 0;

    // Exchange Online: Archive Mailbox
    if args.enable_archive || args.all {
        println!("\n{} Exchange Online Archive Mailboxes...", "→".cyan());

        if args.dry_run {
            println!(
                "  {} Would enable archive mailbox for all users",
                "→".cyan()
            );
        } else {
            match exchange_online::enable_archive_mailbox_tenant_wide(&graph).await {
                Ok(result) => {
                    let total = result["totalUsers"].as_u64().unwrap_or(0);
                    println!("  {} Enabled archive for {} users", "✓".green(), total);
                    configured_count += 1;
                }
                Err(e) => println!("  {} Failed: {}", "✗".red(), e),
            }
        }
    }

    // Exchange Online: Retention Policy
    if args.enable_archive || args.all {
        println!("\n{} Exchange Online Retention Policy...", "→".cyan());

        if args.dry_run {
            println!(
                "  {} Would create retention policy: Archive after {} years",
                "→".cyan(),
                args.archive_after_years
            );
        } else {
            let policy_name = format!("Archive After {} Years", args.archive_after_years);

            match exchange_online::configure_retention_policy(
                &graph,
                &policy_name,
                args.archive_after_years,
            )
            .await
            {
                Ok(policy) => {
                    let policy_id = policy["id"].as_str().unwrap_or("unknown");
                    println!(
                        "  {} Created retention policy: {}",
                        "✓".green(),
                        policy_name
                    );

                    // Apply policy tenant-wide
                    match exchange_online::apply_retention_policy_tenant_wide(&graph, policy_id)
                        .await
                    {
                        Ok(_) => {
                            println!("  {} Applied policy to all mailboxes", "✓".green());
                            configured_count += 1;
                        }
                        Err(e) => println!("  {} Failed to apply policy: {}", "✗".red(), e),
                    }
                }
                Err(e) => println!("  {} Failed: {}", "✗".red(), e),
            }
        }
    }

    // Quarantine Notifications
    if args.disable_quarantine_alerts || args.all {
        println!("\n{} Quarantine Email Notifications...", "→".cyan());

        if args.dry_run {
            println!(
                "  {} Would disable end-user quarantine notifications",
                "→".cyan()
            );
        } else {
            match exchange_online::disable_quarantine_notifications(&graph).await {
                Ok(_) => {
                    println!("  {} Disabled quarantine notifications", "✓".green());
                    configured_count += 1;
                }
                Err(e) => println!("  {} Failed: {}", "✗".red(), e),
            }
        }
    }

    // Anti-Spam Configuration
    if args.configure_spam_filter || args.all {
        println!("\n{} Anti-Spam Policy...", "→".cyan());

        if args.dry_run {
            println!("  {} Would configure strict anti-spam policy", "→".cyan());
        } else {
            let policy_name = format!("{} - Strict Anti-Spam", args.name);

            match exchange_online::configure_antispam_policy(&graph, &policy_name).await {
                Ok(_) => {
                    println!(
                        "  {} Configured anti-spam policy: {}",
                        "✓".green(),
                        policy_name
                    );
                    configured_count += 1;
                }
                Err(e) => println!("  {} Failed: {}", "✗".red(), e),
            }
        }

        println!("\n{} Anti-Malware Policy...", "→".cyan());

        if args.dry_run {
            println!("  {} Would configure anti-malware policy", "→".cyan());
        } else {
            let policy_name = format!("{} - Strict Anti-Malware", args.name);

            match exchange_online::configure_antimalware_policy(&graph, &policy_name).await {
                Ok(_) => {
                    println!(
                        "  {} Configured anti-malware policy: {}",
                        "✓".green(),
                        policy_name
                    );
                    configured_count += 1;
                }
                Err(e) => println!("  {} Failed: {}", "✗".red(), e),
            }
        }

        println!("\n{} Outbound Spam Filter...", "→".cyan());

        if args.dry_run {
            println!(
                "  {} Would configure outbound spam filter (block auto-forwarding)",
                "→".cyan()
            );
        } else {
            match exchange_online::configure_outbound_spam_policy(&graph).await {
                Ok(_) => {
                    println!("  {} Configured outbound spam filter", "✓".green());
                    println!("  {} Blocked external auto-forwarding", "✓".green());
                    configured_count += 1;
                }
                Err(e) => println!("  {} Failed: {}", "✗".red(), e),
            }
        }
    }

    // Defender for Office 365
    if args.defender_office || args.all {
        println!("\n{} Defender for Office 365...", "→".cyan());

        if args.dry_run {
            println!("  {} Would configure Safe Links policy", "→".cyan());
            println!("  {} Would configure Safe Attachments policy", "→".cyan());
        } else {
            // Safe Links
            let safe_links_name = format!("{} - Safe Links", args.name);
            match exchange_online::configure_safe_links_policy(&graph, &safe_links_name).await {
                Ok(_) => {
                    println!(
                        "  {} Configured Safe Links: {}",
                        "✓".green(),
                        safe_links_name
                    );
                    configured_count += 1;
                }
                Err(e) => println!("  {} Failed Safe Links: {}", "✗".red(), e),
            }

            // Safe Attachments
            let safe_attachments_name = format!("{} - Safe Attachments", args.name);
            match exchange_online::configure_safe_attachments_policy(&graph, &safe_attachments_name)
                .await
            {
                Ok(_) => {
                    println!(
                        "  {} Configured Safe Attachments: {}",
                        "✓".green(),
                        safe_attachments_name
                    );
                    configured_count += 1;
                }
                Err(e) => println!("  {} Failed Safe Attachments: {}", "✗".red(), e),
            }
        }
    }

    // Summary
    println!("\n{}", "Configuration Summary:".cyan().bold());
    println!("────────────────────────────────────────────");

    if args.dry_run {
        println!("{} (no changes applied)", "DRY RUN".yellow().bold());
    } else {
        println!(
            "{} Configured {} tenant-wide settings",
            "✓".green().bold(),
            configured_count
        );
    }

    if args.all || (args.enable_archive && args.configure_spam_filter) {
        println!("\n{} Next Steps:", "ℹ".cyan());
        println!("  1. Verify settings in Microsoft 365 Admin Center");
        println!("  2. Test with pilot group of users");
        println!("  3. Monitor Exchange admin center for policy compliance");
        println!("  4. Review Defender for Office 365 reports (if enabled)");
    }

    Ok(())
}

/// Show current tenant configuration
pub async fn show_config() -> Result<()> {
    println!("{} tenant configuration...", "Retrieving".cyan().bold());

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    println!("→ Tenant: {}", active_tenant.name.cyan().bold());

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    println!("\n{}", "Exchange Online Settings:".cyan().bold());

    // Check anti-spam policies
    match exchange_online::list_antispam_policies(&graph).await {
        Ok(policies) => {
            let count = policies["value"].as_array().map(|a| a.len()).unwrap_or(0);
            println!("  Anti-spam policies: {}", count);
        }
        Err(e) => println!("  {} Failed to retrieve policies: {}", "✗".red(), e),
    }

    // Check organization config
    match exchange_online::get_organization_config(&graph).await {
        Ok(org) => {
            if let Some(org_data) = org["value"].as_array().and_then(|a| a.first()) {
                let display_name = org_data["displayName"].as_str().unwrap_or("Unknown");
                println!("  Organization: {}", display_name);
            }
        }
        Err(e) => println!("  {} Failed to retrieve organization: {}", "✗".red(), e),
    }

    Ok(())
}
