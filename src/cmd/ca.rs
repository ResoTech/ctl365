/// Conditional Access policy deployment commands

use crate::config::ConfigManager;
use crate::error::Result;
use crate::graph::{conditional_access, GraphClient};
use crate::tui::change_tracker;
use clap::Args;
use colored::Colorize;

#[derive(Args, Debug)]
pub struct DeployArgs {
    /// Deploy all best practice CA policies
    #[arg(long)]
    pub all: bool,

    /// Deploy MFA enforcement policy
    #[arg(long)]
    pub mfa: bool,

    /// Deploy GeoIP blocking (US + Canada only)
    #[arg(long)]
    pub geoip_block: bool,

    /// Deploy compliant device requirement
    #[arg(long)]
    pub compliant_device: bool,

    /// Deploy legacy auth blocking
    #[arg(long)]
    pub block_legacy_auth: bool,

    /// Deploy admin MFA requirement
    #[arg(long)]
    pub admin_mfa: bool,

    /// Disable security defaults (required for CA)
    #[arg(long)]
    pub disable_security_defaults: bool,

    /// Exclusion group ID (for break-glass accounts)
    #[arg(long)]
    pub exclusion_group: Option<String>,

    /// Start policies in enabled mode (default: report-only)
    #[arg(long)]
    pub enable: bool,

    /// Dry run - show what would be deployed without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

pub async fn deploy(args: DeployArgs) -> Result<()> {
    println!("{} Conditional Access policies...", "Deploying".cyan().bold());

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    println!("→ Active tenant: {}", active_tenant.name.cyan().bold());

    let exclusion_groups = args.exclusion_group.clone().map(|g| vec![g]).unwrap_or_default();

    // Collect policies to deploy
    let mut policies_to_deploy = Vec::new();
    if args.mfa || args.all {
        policies_to_deploy.push("Baseline - Require MFA for All Users");
    }
    if args.geoip_block || args.all {
        policies_to_deploy.push("Baseline - Block Access from Outside US/Canada");
    }
    if args.compliant_device || args.all {
        policies_to_deploy.push("Baseline - Require Compliant Device (Windows, macOS, iOS, Android)");
    }
    if args.block_legacy_auth || args.all {
        policies_to_deploy.push("Baseline - Block Legacy Authentication");
    }
    if args.admin_mfa || args.all {
        policies_to_deploy.push("Baseline - Require MFA for Admins");
    }

    if policies_to_deploy.is_empty() {
        println!("\n{} No policies selected. Use --all or specific flags (--mfa, --geoip-block, etc.)", "ℹ".yellow());
        return Ok(());
    }

    // Dry run mode - show what would be deployed
    if args.dry_run {
        println!("\n{}", "DRY RUN - No changes will be made".yellow().bold());
        println!("\n{} Policies that would be deployed:", "→".cyan());
        for policy in &policies_to_deploy {
            println!("  • {}", policy);
        }
        if args.disable_security_defaults {
            println!("\n{} Security defaults would be disabled", "→".cyan());
        }
        if !exclusion_groups.is_empty() {
            println!("\n{} Exclusion groups: {:?}", "→".cyan(), exclusion_groups);
        }
        println!("\n{} Mode: {}", "→".cyan(), if args.enable { "enabled".green() } else { "report-only".yellow() });
        return Ok(());
    }

    // Confirmation prompt
    if !args.yes {
        use std::io::{self, Write};
        println!("\n{} This will deploy {} CA policies to tenant '{}'",
            "⚠".yellow().bold(),
            policies_to_deploy.len(),
            active_tenant.name
        );
        if args.disable_security_defaults {
            println!("{} Security defaults will be DISABLED", "⚠".yellow().bold());
        }
        print!("\nContinue? [y/N]: ");
        io::stdout().flush()?;

        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        if !response.trim().eq_ignore_ascii_case("y") {
            println!("{}", "Cancelled.".yellow());
            return Ok(());
        }
    }

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Disable security defaults if requested
    if args.disable_security_defaults {
        println!("\n{} Disabling security defaults...", "→".cyan());
        match conditional_access::disable_security_defaults(&graph).await {
            Ok(_) => println!("  {} Security defaults disabled", "✓".green()),
            Err(e) => println!("  {} Failed: {}", "✗".red(), e),
        }
    }

    let mut deployed_policies = Vec::new();

    // Deploy MFA policy
    if args.mfa || args.all {
        println!("\n{} Deploying MFA enforcement policy...", "→".cyan());
        let policy_name = "Baseline - Require MFA for All Users";
        let policy = conditional_access::generate_mfa_policy(
            policy_name,
            exclusion_groups.clone(),
        );
        match conditional_access::create_policy(&graph, &policy).await {
            Ok(result) => {
                println!("  {} MFA policy created", "✓".green());
                change_tracker::record_policy_created("Conditional Access", policy_name, &active_tenant.name);
                deployed_policies.push(result);
            }
            Err(e) => {
                println!("  {} Failed: {}", "✗".red(), e);
                change_tracker::record_error("Conditional Access", policy_name, &e.to_string(), &active_tenant.name);
            }
        }
    }

    // Deploy GeoIP blocking
    if args.geoip_block || args.all {
        println!("\n{} Deploying GeoIP blocking (US + Canada)...", "→".cyan());
        let policy_name = "Baseline - Block Access from Outside US/Canada";

        // First create the named location
        let location = conditional_access::generate_us_canada_location("Allowed Countries - US and Canada");
        match conditional_access::create_named_location(&graph, &location).await {
            Ok(location_result) => {
                let location_id = location_result["id"].as_str().unwrap_or("");
                println!("  {} Named Location created: {}", "✓".green(), location_id);

                // Then create the blocking policy
                let policy = conditional_access::generate_geoip_block_policy(
                    policy_name,
                    location_id,
                    exclusion_groups.clone(),
                );
                match conditional_access::create_policy(&graph, &policy).await {
                    Ok(result) => {
                        println!("  {} GeoIP block policy created", "✓".green());
                        change_tracker::record_policy_created("Conditional Access", policy_name, &active_tenant.name);
                        deployed_policies.push(result);
                    }
                    Err(e) => {
                        println!("  {} Failed to create policy: {}", "✗".red(), e);
                        change_tracker::record_error("Conditional Access", policy_name, &e.to_string(), &active_tenant.name);
                    }
                }
            }
            Err(e) => {
                println!("  {} Failed to create Named Location: {}", "✗".red(), e);
                change_tracker::record_error("Conditional Access", "Named Location", &e.to_string(), &active_tenant.name);
            }
        }
    }

    // Deploy compliant device requirement
    if args.compliant_device || args.all {
        println!("\n{} Deploying compliant device policies...", "→".cyan());

        for platform in &["windows", "macos", "ios", "android"] {
            let policy_name = format!("Baseline - Require Compliant Device - {}", platform.to_uppercase());
            let policy = conditional_access::generate_compliant_device_policy(
                &policy_name,
                platform,
                exclusion_groups.clone(),
            );
            match conditional_access::create_policy(&graph, &policy).await {
                Ok(result) => {
                    println!("  {} {} compliant device policy created", "✓".green(), platform);
                    change_tracker::record_policy_created("Conditional Access", &policy_name, &active_tenant.name);
                    deployed_policies.push(result);
                }
                Err(e) => {
                    println!("  {} Failed {}: {}", "✗".red(), platform, e);
                    change_tracker::record_error("Conditional Access", &policy_name, &e.to_string(), &active_tenant.name);
                }
            }
        }
    }

    // Deploy legacy auth blocking
    if args.block_legacy_auth || args.all {
        println!("\n{} Deploying legacy authentication block...", "→".cyan());
        let policy_name = "Baseline - Block Legacy Authentication";
        let policy = conditional_access::generate_block_legacy_auth_policy(
            policy_name,
            exclusion_groups.clone(),
        );
        match conditional_access::create_policy(&graph, &policy).await {
            Ok(result) => {
                println!("  {} Legacy auth block policy created", "✓".green());
                change_tracker::record_policy_created("Conditional Access", policy_name, &active_tenant.name);
                deployed_policies.push(result);
            }
            Err(e) => {
                println!("  {} Failed: {}", "✗".red(), e);
                change_tracker::record_error("Conditional Access", policy_name, &e.to_string(), &active_tenant.name);
            }
        }
    }

    // Deploy admin MFA
    if args.admin_mfa || args.all {
        println!("\n{} Deploying admin MFA requirement...", "→".cyan());
        let policy_name = "Baseline - Require MFA for Admins";
        let policy = conditional_access::generate_admin_mfa_policy(policy_name);
        match conditional_access::create_policy(&graph, &policy).await {
            Ok(result) => {
                println!("  {} Admin MFA policy created", "✓".green());
                change_tracker::record_policy_created("Conditional Access", policy_name, &active_tenant.name);
                deployed_policies.push(result);
            }
            Err(e) => {
                println!("  {} Failed: {}", "✗".red(), e);
                change_tracker::record_error("Conditional Access", policy_name, &e.to_string(), &active_tenant.name);
            }
        }
    }

    // Enable policies if requested
    if args.enable && !deployed_policies.is_empty() {
        println!("\n{} Enabling policies...", "→".cyan().bold());
        for policy in &deployed_policies {
            let policy_id = policy["id"].as_str().unwrap_or("");
            let policy_name = policy["displayName"].as_str().unwrap_or("Unknown");

            match conditional_access::enable_policy(&graph, policy_id).await {
                Ok(_) => println!("  {} Enabled: {}", "✓".green(), policy_name),
                Err(e) => println!("  {} Failed {}: {}", "✗".red(), policy_name, e),
            }
        }
    } else if !deployed_policies.is_empty() {
        println!("\n{} All policies created in REPORT-ONLY mode", "ℹ".yellow().bold());
        println!("   Review sign-in logs before enabling with: ctl365 ca enable --policy <id>");
    }

    println!("\n{} Successfully deployed {} CA policies", "✓".green().bold(), deployed_policies.len());

    Ok(())
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Show verbose details
    #[arg(short, long)]
    pub verbose: bool,

    /// Filter by state (enabled, report-only, disabled)
    #[arg(long)]
    pub state: Option<String>,
}

/// List Conditional Access policies in the tenant
pub async fn list(args: ListArgs) -> Result<()> {
    println!("{} Conditional Access policies...", "Listing".cyan().bold());

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    println!("→ Tenant: {}", active_tenant.name.cyan().bold());

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    match conditional_access::list_policies(&graph).await {
        Ok(policies) => {
            let policy_list = policies["value"].as_array();

            if let Some(list) = policy_list {
                if list.is_empty() {
                    println!("\n{} No Conditional Access policies found", "ℹ".yellow());
                    return Ok(());
                }

                // Count by state
                let enabled = list.iter().filter(|p| p["state"].as_str() == Some("enabled")).count();
                let report_only = list.iter().filter(|p| p["state"].as_str() == Some("enabledForReportingButNotEnforced")).count();
                let disabled = list.iter().filter(|p| p["state"].as_str() == Some("disabled")).count();

                println!("\n{} {} CA policies found ({} enabled, {} report-only, {} disabled)\n",
                    "→".cyan(),
                    list.len(),
                    enabled.to_string().green(),
                    report_only.to_string().yellow(),
                    disabled.to_string().red()
                );

                // Filter if state specified
                let filtered: Vec<_> = if let Some(state_filter) = &args.state {
                    let filter_state = match state_filter.as_str() {
                        "enabled" => "enabled",
                        "report-only" | "reportonly" => "enabledForReportingButNotEnforced",
                        "disabled" => "disabled",
                        _ => state_filter.as_str(),
                    };
                    list.iter().filter(|p| p["state"].as_str() == Some(filter_state)).collect()
                } else {
                    list.iter().collect()
                };

                // Print header
                println!("{:<50} {:<15} {:<12}",
                    "Name".bold(),
                    "State".bold(),
                    "Created".bold()
                );
                println!("{}", "─".repeat(80));

                for policy in filtered {
                    let name = policy["displayName"].as_str().unwrap_or("Unknown");
                    let state = policy["state"].as_str().unwrap_or("unknown");
                    let created = policy["createdDateTime"]
                        .as_str()
                        .unwrap_or("")
                        .split('T')
                        .next()
                        .unwrap_or("");

                    let state_display = match state {
                        "enabled" => state.green().to_string(),
                        "enabledForReportingButNotEnforced" => "report-only".yellow().to_string(),
                        "disabled" => state.red().to_string(),
                        _ => state.to_string(),
                    };

                    // Truncate name if too long
                    let name_display = if name.len() > 48 {
                        format!("{}...", &name[..45])
                    } else {
                        name.to_string()
                    };

                    println!("{:<50} {:<15} {:<12}",
                        name_display,
                        state_display,
                        created
                    );

                    if args.verbose {
                        let id = policy["id"].as_str().unwrap_or("");
                        let modified = policy["modifiedDateTime"]
                            .as_str()
                            .unwrap_or("")
                            .split('T')
                            .next()
                            .unwrap_or("");
                        println!("   ID: {}", id.dimmed());
                        println!("   Modified: {}", modified.dimmed());
                        println!();
                    }
                }
            } else {
                println!("{} No policies found or unexpected response format", "✗".red());
            }
        }
        Err(e) => {
            println!("{} Failed to list policies: {}", "✗".red(), e);
        }
    }

    Ok(())
}
