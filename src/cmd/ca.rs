/// Conditional Access policy deployment commands
use crate::config::ConfigManager;
use crate::error::Result;
use crate::graph::{GraphClient, conditional_access};
use crate::templates::ca_baseline_2025::{CABaseline2025, CAPolicyTemplate, BlastRadius};
use crate::tui::change_tracker;
use clap::Args;
use colored::Colorize;
use serde_json::Value;

#[derive(Args, Debug)]
pub struct DeployArgs {
    /// Deploy all best practice CA policies
    #[arg(long)]
    pub all: bool,

    /// Deploy a complete CA baseline (e.g., "2025" for 46-policy comprehensive baseline)
    #[arg(long, value_name = "NAME")]
    pub baseline: Option<String>,

    /// Filter baseline policies by category (CAD, CAL, CAP, CAR, CAS, CAU)
    #[arg(long, value_name = "CATEGORY")]
    pub category: Option<String>,

    /// Deploy specific policy by ID (e.g., CAD001, CAU001)
    #[arg(long, value_name = "ID")]
    pub policy: Option<String>,

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
    println!(
        "{} Conditional Access policies...",
        "Deploying".cyan().bold()
    );

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    println!("→ Active tenant: {}", active_tenant.name.cyan().bold());

    // Handle baseline deployment
    if let Some(baseline_name) = &args.baseline {
        return deploy_baseline(&args, baseline_name, &config, &active_tenant.name).await;
    }

    let exclusion_groups = args
        .exclusion_group
        .clone()
        .map(|g| vec![g])
        .unwrap_or_default();

    // Collect policies to deploy
    let mut policies_to_deploy = Vec::new();
    if args.mfa || args.all {
        policies_to_deploy.push("Baseline - Require MFA for All Users");
    }
    if args.geoip_block || args.all {
        policies_to_deploy.push("Baseline - Block Access from Outside US/Canada");
    }
    if args.compliant_device || args.all {
        policies_to_deploy
            .push("Baseline - Require Compliant Device (Windows, macOS, iOS, Android)");
    }
    if args.block_legacy_auth || args.all {
        policies_to_deploy.push("Baseline - Block Legacy Authentication");
    }
    if args.admin_mfa || args.all {
        policies_to_deploy.push("Baseline - Require MFA for Admins");
    }

    if policies_to_deploy.is_empty() {
        println!(
            "\n{} No policies selected. Use --all or specific flags (--mfa, --geoip-block, etc.)",
            "ℹ".yellow()
        );
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
        println!(
            "\n{} Mode: {}",
            "→".cyan(),
            if args.enable {
                "enabled".green()
            } else {
                "report-only".yellow()
            }
        );
        return Ok(());
    }

    // Confirmation prompt
    if !args.yes {
        use std::io::{self, Write};
        println!(
            "\n{} This will deploy {} CA policies to tenant '{}'",
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
        let policy = conditional_access::generate_mfa_policy(policy_name, exclusion_groups.clone());
        match conditional_access::create_policy(&graph, &policy).await {
            Ok(result) => {
                println!("  {} MFA policy created", "✓".green());
                change_tracker::record_policy_created(
                    "Conditional Access",
                    policy_name,
                    &active_tenant.name,
                );
                deployed_policies.push(result);
            }
            Err(e) => {
                println!("  {} Failed: {}", "✗".red(), e);
                change_tracker::record_error(
                    "Conditional Access",
                    policy_name,
                    &e.to_string(),
                    &active_tenant.name,
                );
            }
        }
    }

    // Deploy GeoIP blocking
    if args.geoip_block || args.all {
        println!("\n{} Deploying GeoIP blocking (US + Canada)...", "→".cyan());
        let policy_name = "Baseline - Block Access from Outside US/Canada";

        // First create the named location
        let location =
            conditional_access::generate_us_canada_location("Allowed Countries - US and Canada");
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
                        change_tracker::record_policy_created(
                            "Conditional Access",
                            policy_name,
                            &active_tenant.name,
                        );
                        deployed_policies.push(result);
                    }
                    Err(e) => {
                        println!("  {} Failed to create policy: {}", "✗".red(), e);
                        change_tracker::record_error(
                            "Conditional Access",
                            policy_name,
                            &e.to_string(),
                            &active_tenant.name,
                        );
                    }
                }
            }
            Err(e) => {
                println!("  {} Failed to create Named Location: {}", "✗".red(), e);
                change_tracker::record_error(
                    "Conditional Access",
                    "Named Location",
                    &e.to_string(),
                    &active_tenant.name,
                );
            }
        }
    }

    // Deploy compliant device requirement
    if args.compliant_device || args.all {
        println!("\n{} Deploying compliant device policies...", "→".cyan());

        for platform in &["windows", "macos", "ios", "android"] {
            let policy_name = format!(
                "Baseline - Require Compliant Device - {}",
                platform.to_uppercase()
            );
            let policy = conditional_access::generate_compliant_device_policy(
                &policy_name,
                platform,
                exclusion_groups.clone(),
            );
            match conditional_access::create_policy(&graph, &policy).await {
                Ok(result) => {
                    println!(
                        "  {} {} compliant device policy created",
                        "✓".green(),
                        platform
                    );
                    change_tracker::record_policy_created(
                        "Conditional Access",
                        &policy_name,
                        &active_tenant.name,
                    );
                    deployed_policies.push(result);
                }
                Err(e) => {
                    println!("  {} Failed {}: {}", "✗".red(), platform, e);
                    change_tracker::record_error(
                        "Conditional Access",
                        &policy_name,
                        &e.to_string(),
                        &active_tenant.name,
                    );
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
                change_tracker::record_policy_created(
                    "Conditional Access",
                    policy_name,
                    &active_tenant.name,
                );
                deployed_policies.push(result);
            }
            Err(e) => {
                println!("  {} Failed: {}", "✗".red(), e);
                change_tracker::record_error(
                    "Conditional Access",
                    policy_name,
                    &e.to_string(),
                    &active_tenant.name,
                );
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
                change_tracker::record_policy_created(
                    "Conditional Access",
                    policy_name,
                    &active_tenant.name,
                );
                deployed_policies.push(result);
            }
            Err(e) => {
                println!("  {} Failed: {}", "✗".red(), e);
                change_tracker::record_error(
                    "Conditional Access",
                    policy_name,
                    &e.to_string(),
                    &active_tenant.name,
                );
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
        println!(
            "\n{} All policies created in REPORT-ONLY mode",
            "ℹ".yellow().bold()
        );
        println!("   Review sign-in logs before enabling with: ctl365 ca enable --policy <id>");
    }

    println!(
        "\n{} Successfully deployed {} CA policies",
        "✓".green().bold(),
        deployed_policies.len()
    );

    Ok(())
}

/// Deploy a complete CA baseline (e.g., 2025)
async fn deploy_baseline(
    args: &DeployArgs,
    baseline_name: &str,
    config: &ConfigManager,
    tenant_name: &str,
) -> Result<()> {
    // Validate baseline name
    if baseline_name != "2025" {
        println!(
            "{} Unknown baseline: '{}'. Available baselines: 2025",
            "✗".red(),
            baseline_name
        );
        return Ok(());
    }

    println!(
        "\n{} CA Baseline 2025 - Kenneth van Surksum + Daniel Chronlund",
        "→".cyan().bold()
    );
    println!("   Based on: https://www.vansurksum.com/\n");

    // Generate baseline
    let baseline = CABaseline2025::generate();
    
    // Filter policies based on args
    let policies_to_deploy: Vec<&CAPolicyTemplate> = if let Some(policy_id) = &args.policy {
        // Deploy single policy by ID
        baseline
            .policies
            .iter()
            .filter(|p| p.id.eq_ignore_ascii_case(policy_id))
            .collect()
    } else if let Some(category) = &args.category {
        // Deploy by category (CAD, CAL, CAP, CAR, CAS, CAU)
        let category_upper = category.to_uppercase();
        baseline
            .policies
            .iter()
            .filter(|p| p.id.starts_with(&category_upper))
            .collect()
    } else {
        // Deploy all
        baseline.policies.iter().collect()
    };

    if policies_to_deploy.is_empty() {
        if let Some(policy_id) = &args.policy {
            println!("{} Policy '{}' not found in baseline", "✗".red(), policy_id);
            println!("\n{} Available policy IDs:", "ℹ".yellow());
            for p in &baseline.policies {
                println!("   {} - {}", p.id.cyan(), p.display_name);
            }
        } else if let Some(category) = &args.category {
            println!(
                "{} No policies found for category '{}'",
                "✗".red(),
                category
            );
            println!("\n{} Available categories: CAD, CAL, CAP, CAR, CAS, CAU", "ℹ".yellow());
        }
        return Ok(());
    }

    // Count by blast radius
    let critical_count = policies_to_deploy
        .iter()
        .filter(|p| p.blast_radius == BlastRadius::Critical)
        .count();
    let high_count = policies_to_deploy
        .iter()
        .filter(|p| p.blast_radius == BlastRadius::High)
        .count();

    // Summary
    println!(
        "{} {} policies to deploy:",
        "→".cyan(),
        policies_to_deploy.len()
    );
    
    // Group by category for display
    let categories = ["CAD", "CAL", "CAP", "CAR", "CAS", "CAU"];
    for cat in &categories {
        let count = policies_to_deploy
            .iter()
            .filter(|p| p.id.starts_with(cat))
            .count();
        if count > 0 {
            let desc = match *cat {
                "CAD" => "Device/Platform",
                "CAL" => "Location",
                "CAP" => "Protocol/Legacy Auth",
                "CAR" => "Risk-based",
                "CAS" => "Service-specific",
                "CAU" => "User-based",
                _ => "Other",
            };
            println!("   {} {} ({} policies)", cat.cyan(), desc, count);
        }
    }

    println!();
    if critical_count > 0 {
        println!(
            "   {} {} CRITICAL impact policies (all users + all apps)",
            "⚠".red().bold(),
            critical_count
        );
    }
    if high_count > 0 {
        println!(
            "   {} {} HIGH impact policies",
            "⚠".yellow(),
            high_count
        );
    }

    // Dry run mode
    if args.dry_run {
        println!("\n{}", "DRY RUN - No changes will be made".yellow().bold());
        println!("\n{} Policies that would be deployed:\n", "→".cyan());
        
        for policy in &policies_to_deploy {
            let blast_display = match policy.blast_radius {
                BlastRadius::Critical => "CRITICAL".red().bold().to_string(),
                BlastRadius::High => "HIGH".yellow().bold().to_string(),
                BlastRadius::Medium => "MEDIUM".white().to_string(),
                BlastRadius::Low => "LOW".green().to_string(),
            };
            println!(
                "  {} {} [{}]",
                policy.id.cyan(),
                policy.display_name,
                blast_display
            );
            println!("      {}", policy.impact_summary.dimmed());
        }

        println!("\n{} Named locations that would be created:", "→".cyan());
        for loc in &baseline.named_locations {
            println!("  • {} ({})", loc.display_name, loc.location_type);
        }

        println!(
            "\n{} Mode: {}",
            "→".cyan(),
            if args.enable {
                "ENABLED (enforcing)".red().bold()
            } else {
                "report-only (safe)".green()
            }
        );
        return Ok(());
    }

    // Confirmation prompt
    if !args.yes {
        use std::io::{self, Write};
        println!(
            "\n{} This will deploy {} CA policies to tenant '{}'",
            "⚠".yellow().bold(),
            policies_to_deploy.len(),
            tenant_name
        );
        if args.disable_security_defaults {
            println!(
                "{} Security defaults will be DISABLED",
                "⚠".yellow().bold()
            );
        }
        println!(
            "\n{} All policies will be created in {} mode",
            "ℹ".cyan(),
            if args.enable {
                "ENABLED".red().bold()
            } else {
                "REPORT-ONLY".green()
            }
        );
        print!("\nContinue? [y/N]: ");
        io::stdout().flush()?;

        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        if !response.trim().eq_ignore_ascii_case("y") {
            println!("{}", "Cancelled.".yellow());
            return Ok(());
        }
    }

    let graph = GraphClient::from_config(config, tenant_name).await?;

    // Disable security defaults if requested
    if args.disable_security_defaults {
        println!("\n{} Disabling security defaults...", "→".cyan());
        match conditional_access::disable_security_defaults(&graph).await {
            Ok(_) => println!("  {} Security defaults disabled", "✓".green()),
            Err(e) => println!("  {} Failed: {}", "✗".red(), e),
        }
    }

    // Create named locations first (some policies depend on them)
    println!("\n{} Creating named locations...", "→".cyan().bold());
    let mut location_ids: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    
    for loc in &baseline.named_locations {
        let location_json = if loc.location_type == "country" {
            serde_json::json!({
                "@odata.type": "#microsoft.graph.countryNamedLocation",
                "displayName": loc.display_name,
                "countriesAndRegions": loc.countries,
                "includeUnknownCountriesAndRegions": false
            })
        } else {
            // IP-based location
            let ip_ranges: Vec<Value> = loc
                .ip_ranges
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(|ip| {
                    serde_json::json!({
                        "@odata.type": "#microsoft.graph.iPv4CidrRange",
                        "cidrAddress": ip
                    })
                })
                .collect();
            serde_json::json!({
                "@odata.type": "#microsoft.graph.ipNamedLocation",
                "displayName": loc.display_name,
                "isTrusted": true,
                "ipRanges": ip_ranges
            })
        };

        match conditional_access::create_named_location(&graph, &location_json).await {
            Ok(result) => {
                let loc_id = result["id"].as_str().unwrap_or("").to_string();
                println!("  {} {} (ID: {})", "✓".green(), loc.display_name, loc_id.dimmed());
                location_ids.insert(loc.display_name.clone(), loc_id);
            }
            Err(e) => {
                // Check if already exists
                let err_str = e.to_string();
                if err_str.contains("already exists") || err_str.contains("409") {
                    println!("  {} {} (already exists)", "ℹ".yellow(), loc.display_name);
                } else {
                    println!("  {} {} - {}", "✗".red(), loc.display_name, e);
                }
            }
        }
    }

    // Deploy policies
    println!("\n{} Deploying CA policies...", "→".cyan().bold());
    let mut deployed_count = 0;
    let mut failed_count = 0;

    for policy in &policies_to_deploy {
        // Convert template to Graph API JSON
        let mut policy_json = CABaseline2025::to_graph_json(policy);

        // Replace placeholder groups with actual exclusion group if provided
        if let Some(exclusion_group_id) = &args.exclusion_group {
            replace_group_placeholders(&mut policy_json, exclusion_group_id);
        } else {
            // Remove placeholder groups (they'd cause API errors)
            remove_group_placeholders(&mut policy_json);
        }

        // Set state based on --enable flag
        if args.enable {
            policy_json["state"] = serde_json::json!("enabled");
        }

        // Create the policy
        match conditional_access::create_policy(&graph, &policy_json).await {
            Ok(_result) => {
                let blast_icon = match policy.blast_radius {
                    BlastRadius::Critical => "⚠".red().to_string(),
                    BlastRadius::High => "⚠".yellow().to_string(),
                    _ => "✓".green().to_string(),
                };
                println!("  {} {} - {}", blast_icon, policy.id.cyan(), policy.display_name);
                change_tracker::record_policy_created(
                    "Conditional Access",
                    &policy.display_name,
                    tenant_name,
                );
                deployed_count += 1;
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("already exists") || err_str.contains("409") {
                    println!(
                        "  {} {} - {} (already exists)",
                        "ℹ".yellow(),
                        policy.id,
                        policy.display_name
                    );
                } else {
                    println!(
                        "  {} {} - {} - {}",
                        "✗".red(),
                        policy.id,
                        policy.display_name,
                        err_str
                    );
                    change_tracker::record_error(
                        "Conditional Access",
                        &policy.display_name,
                        &err_str,
                        tenant_name,
                    );
                    failed_count += 1;
                }
            }
        }
    }

    // Summary
    println!();
    if deployed_count > 0 {
        println!(
            "{} Successfully deployed {} CA policies",
            "✓".green().bold(),
            deployed_count
        );
    }
    if failed_count > 0 {
        println!(
            "{} {} policies failed to deploy",
            "✗".red().bold(),
            failed_count
        );
    }

    if !args.enable {
        println!(
            "\n{} All policies created in REPORT-ONLY mode",
            "ℹ".yellow().bold()
        );
        println!("   Review sign-in logs in Azure Portal before enabling");
        println!("   Enable with: ctl365 ca enable --policy <id>");
    } else {
        println!(
            "\n{} Policies are ENABLED and ENFORCING",
            "⚠".red().bold()
        );
        println!("   Monitor sign-in logs for any access issues");
    }

    Ok(())
}

/// Replace placeholder group IDs with actual exclusion group
fn replace_group_placeholders(policy: &mut Value, exclusion_group_id: &str) {
    if let Some(conditions) = policy.get_mut("conditions") {
        if let Some(users) = conditions.get_mut("users") {
            // Replace excludeGroups placeholders
            if let Some(exclude_groups) = users.get_mut("excludeGroups") {
                if let Some(arr) = exclude_groups.as_array_mut() {
                    for item in arr.iter_mut() {
                        if let Some(s) = item.as_str() {
                            if s.starts_with("{{") && s.ends_with("}}") {
                                *item = serde_json::json!(exclusion_group_id);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Remove placeholder groups (they'd cause API errors)
fn remove_group_placeholders(policy: &mut Value) {
    if let Some(conditions) = policy.get_mut("conditions") {
        if let Some(users) = conditions.get_mut("users") {
            // Remove excludeGroups with placeholders
            if let Some(exclude_groups) = users.get_mut("excludeGroups") {
                if let Some(arr) = exclude_groups.as_array_mut() {
                    arr.retain(|item| {
                        if let Some(s) = item.as_str() {
                            !s.starts_with("{{")
                        } else {
                            true
                        }
                    });
                }
            }
        }
    }
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Show verbose details
    #[arg(short, long)]
    pub verbose: bool,

    /// Filter by state (enabled, report-only, disabled)
    #[arg(long)]
    pub state: Option<String>,

    /// Show detailed policy information (conditions, controls)
    #[arg(long)]
    pub details: bool,

    /// Output format (table, json)
    #[arg(short, long, default_value = "table")]
    pub format: String,
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
                    println!();
                    println!("  {}:", "Possible reasons".white().bold());
                    println!("    • No CA policies have been created in this tenant");
                    println!("    • The App Registration may be missing the required permission:");
                    println!("      {}", "Policy.Read.All or Policy.ReadWrite.ConditionalAccess".yellow());
                    println!("    • Admin consent may not have been granted");
                    println!();
                    println!("  {}:", "To verify permissions".white().bold());
                    println!("    1. Go to Azure Portal → App registrations → Your app");
                    println!("    2. Check API permissions for: {}", "Policy.Read.All".cyan());
                    println!("    3. Ensure admin consent has been granted (green checkmark)");
                    return Ok(());
                }

                // JSON output
                if args.format == "json" {
                    println!("{}", serde_json::to_string_pretty(&policies)?);
                    return Ok(());
                }

                // Count by state
                let enabled = list
                    .iter()
                    .filter(|p| p["state"].as_str() == Some("enabled"))
                    .count();
                let report_only = list
                    .iter()
                    .filter(|p| p["state"].as_str() == Some("enabledForReportingButNotEnforced"))
                    .count();
                let disabled = list
                    .iter()
                    .filter(|p| p["state"].as_str() == Some("disabled"))
                    .count();

                println!(
                    "\n{} {} CA policies found ({} enabled, {} report-only, {} disabled)\n",
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
                    list.iter()
                        .filter(|p| p["state"].as_str() == Some(filter_state))
                        .collect()
                } else {
                    list.iter().collect()
                };

                // Print header
                if args.details {
                    // Detailed view
                    for (i, policy) in filtered.iter().enumerate() {
                        if i > 0 {
                            println!("{}", "─".repeat(80));
                        }
                        print_policy_details(policy);
                    }
                } else {
                    // Table view
                    println!(
                        "{:<50} {:<15} {:<12}",
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

                        // Truncate name if too long (char-safe for UTF-8)
                        let name_display = if name.chars().count() > 48 {
                            let truncated: String = name.chars().take(45).collect();
                            format!("{}...", truncated)
                        } else {
                            name.to_string()
                        };

                        println!("{:<50} {:<15} {:<12}", name_display, state_display, created);

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
                            
                            // Show quick summary of conditions
                            if let Some(conditions) = policy.get("conditions") {
                                print_conditions_summary(conditions);
                            }
                            if let Some(grant_controls) = policy.get("grantControls") {
                                print_grant_controls_summary(grant_controls);
                            }
                            println!();
                        }
                    }
                }
            } else {
                println!(
                    "{} No policies found or unexpected response format",
                    "✗".red()
                );
                println!();
                println!("  This usually indicates a permission issue.");
                println!("  Ensure your App Registration has:");
                println!("    • {} permission", "Policy.Read.All".yellow());
                println!("    • Admin consent granted");
            }
        }
        Err(e) => {
            println!("{} Failed to list policies: {}", "✗".red(), e);
            println!();
            println!("  {}:", "Common causes".white().bold());
            println!("    • Missing permission: {}", "Policy.Read.All".yellow());
            println!("    • Token expired - try: {}", "ctl365 login".cyan());
            println!("    • Network connectivity issue");
        }
    }

    Ok(())
}

/// Print detailed policy information
fn print_policy_details(policy: &serde_json::Value) {
    let name = policy["displayName"].as_str().unwrap_or("Unknown");
    let state = policy["state"].as_str().unwrap_or("unknown");
    let id = policy["id"].as_str().unwrap_or("");
    let created = policy["createdDateTime"].as_str().unwrap_or("").split('T').next().unwrap_or("");
    let modified = policy["modifiedDateTime"].as_str().unwrap_or("").split('T').next().unwrap_or("");

    let state_display = match state {
        "enabled" => "ENABLED".green().bold().to_string(),
        "enabledForReportingButNotEnforced" => "REPORT-ONLY".yellow().bold().to_string(),
        "disabled" => "DISABLED".red().bold().to_string(),
        _ => state.to_string(),
    };

    println!();
    println!("  {} {}", "Policy:".white().bold(), name.cyan().bold());
    println!("  {} {}", "State:".white().bold(), state_display);
    println!("  {} {}", "ID:".dimmed(), id.dimmed());
    println!("  {} {} | {} {}", "Created:".dimmed(), created.dimmed(), "Modified:".dimmed(), modified.dimmed());
    
    // Conditions
    if let Some(conditions) = policy.get("conditions") {
        println!();
        println!("  {}:", "Conditions".white().bold());
        
        // Users
        if let Some(users) = conditions.get("users") {
            print!("    {} ", "Users:".cyan());
            let include_users = users.get("includeUsers").and_then(|v| v.as_array());
            let include_groups = users.get("includeGroups").and_then(|v| v.as_array());
            let include_roles = users.get("includeRoles").and_then(|v| v.as_array());
            
            if let Some(inc) = include_users {
                if inc.iter().any(|u| u.as_str() == Some("All")) {
                    print!("{}", "All users".green());
                } else if inc.iter().any(|u| u.as_str() == Some("GuestsOrExternalUsers")) {
                    print!("{}", "Guests/External".yellow());
                } else if !inc.is_empty() {
                    print!("{} specific users", inc.len());
                }
            }
            if let Some(groups) = include_groups {
                if !groups.is_empty() {
                    print!(", {} groups", groups.len());
                }
            }
            if let Some(roles) = include_roles {
                if !roles.is_empty() {
                    print!(", {} admin roles", roles.len().to_string().yellow());
                }
            }
            
            // Exclusions
            let exclude_users = users.get("excludeUsers").and_then(|v| v.as_array());
            let exclude_groups = users.get("excludeGroups").and_then(|v| v.as_array());
            if let Some(exc) = exclude_users {
                if !exc.is_empty() {
                    print!(" (excl: {} users)", exc.len());
                }
            }
            if let Some(exc) = exclude_groups {
                if !exc.is_empty() {
                    print!(" (excl: {} groups)", exc.len());
                }
            }
            println!();
        }
        
        // Applications
        if let Some(apps) = conditions.get("applications") {
            print!("    {} ", "Apps:".cyan());
            let include_apps = apps.get("includeApplications").and_then(|v| v.as_array());
            if let Some(inc) = include_apps {
                if inc.iter().any(|a| a.as_str() == Some("All")) {
                    print!("{}", "All apps".green());
                } else if inc.iter().any(|a| a.as_str() == Some("Office365")) {
                    print!("{}", "Office 365".blue());
                } else if inc.iter().any(|a| a.as_str() == Some("MicrosoftAdminPortals")) {
                    print!("{}", "Admin Portals".yellow());
                } else if !inc.is_empty() {
                    print!("{} specific apps", inc.len());
                }
            }
            println!();
        }
        
        // Platforms
        if let Some(platforms) = conditions.get("platforms") {
            if let Some(inc) = platforms.get("includePlatforms").and_then(|v| v.as_array()) {
                if !inc.is_empty() {
                    let platform_list: Vec<&str> = inc.iter()
                        .filter_map(|p| p.as_str())
                        .collect();
                    println!("    {} {}", "Platforms:".cyan(), platform_list.join(", "));
                }
            }
        }
        
        // Locations
        if let Some(locations) = conditions.get("locations") {
            let include_locs = locations.get("includeLocations").and_then(|v| v.as_array());
            let exclude_locs = locations.get("excludeLocations").and_then(|v| v.as_array());
            if include_locs.is_some() || exclude_locs.is_some() {
                print!("    {} ", "Locations:".cyan());
                if let Some(inc) = include_locs {
                    if inc.iter().any(|l| l.as_str() == Some("All")) {
                        print!("All locations");
                    } else if inc.iter().any(|l| l.as_str() == Some("AllTrusted")) {
                        print!("{}", "Trusted only".green());
                    }
                }
                if let Some(exc) = exclude_locs {
                    if !exc.is_empty() {
                        print!(" (excl: {} locations)", exc.len());
                    }
                }
                println!();
            }
        }
        
        // Client app types
        if let Some(client_types) = conditions.get("clientAppTypes").and_then(|v| v.as_array()) {
            if !client_types.is_empty() && !client_types.iter().any(|t| t.as_str() == Some("all")) {
                let types: Vec<&str> = client_types.iter()
                    .filter_map(|t| t.as_str())
                    .collect();
                println!("    {} {}", "Client types:".cyan(), types.join(", "));
            }
        }
        
        // Risk levels
        if let Some(sign_in_risk) = conditions.get("signInRiskLevels").and_then(|v| v.as_array()) {
            if !sign_in_risk.is_empty() {
                let levels: Vec<&str> = sign_in_risk.iter().filter_map(|l| l.as_str()).collect();
                println!("    {} {}", "Sign-in risk:".cyan(), levels.join(", ").yellow());
            }
        }
        if let Some(user_risk) = conditions.get("userRiskLevels").and_then(|v| v.as_array()) {
            if !user_risk.is_empty() {
                let levels: Vec<&str> = user_risk.iter().filter_map(|l| l.as_str()).collect();
                println!("    {} {}", "User risk:".cyan(), levels.join(", ").yellow());
            }
        }
    }
    
    // Grant controls
    if let Some(grant_controls) = policy.get("grantControls") {
        println!();
        println!("  {}:", "Grant Controls".white().bold());
        
        if let Some(controls) = grant_controls.get("builtInControls").and_then(|v| v.as_array()) {
            let operator = grant_controls.get("operator").and_then(|v| v.as_str()).unwrap_or("OR");
            for control in controls {
                let control_str = control.as_str().unwrap_or("");
                let display = match control_str {
                    "mfa" => "Require MFA".green().to_string(),
                    "compliantDevice" => "Require compliant device".green().to_string(),
                    "domainJoinedDevice" => "Require Hybrid Azure AD join".green().to_string(),
                    "approvedApplication" => "Require approved app".green().to_string(),
                    "compliantApplication" => "Require app protection policy".green().to_string(),
                    "passwordChange" => "Require password change".yellow().to_string(),
                    "block" => "BLOCK ACCESS".red().bold().to_string(),
                    _ => control_str.to_string(),
                };
                println!("    • {}", display);
            }
            if controls.len() > 1 {
                println!("    {} {}", "Operator:".dimmed(), operator.to_uppercase().cyan());
            }
        }
    }
    
    // Session controls
    if let Some(session) = policy.get("sessionControls") {
        if !session.is_null() {
            let has_session_controls = session.get("signInFrequency").is_some() 
                || session.get("persistentBrowser").is_some()
                || session.get("cloudAppSecurity").is_some();
            
            if has_session_controls {
                println!();
                println!("  {}:", "Session Controls".white().bold());
                
                if let Some(freq) = session.get("signInFrequency") {
                    if freq.get("isEnabled").and_then(|v| v.as_bool()).unwrap_or(false) {
                        let value = freq.get("value").and_then(|v| v.as_i64()).unwrap_or(0);
                        let freq_type = freq.get("type").and_then(|v| v.as_str()).unwrap_or("hours");
                        println!("    • Sign-in frequency: {} {}", value, freq_type);
                    }
                }
                if let Some(persist) = session.get("persistentBrowser") {
                    if persist.get("isEnabled").and_then(|v| v.as_bool()).unwrap_or(false) {
                        let mode = persist.get("mode").and_then(|v| v.as_str()).unwrap_or("always");
                        println!("    • Persistent browser: {}", mode);
                    }
                }
            }
        }
    }
}

/// Print conditions summary (for verbose mode)
fn print_conditions_summary(conditions: &serde_json::Value) {
    let mut parts = Vec::new();
    
    if let Some(users) = conditions.get("users") {
        if let Some(inc) = users.get("includeUsers").and_then(|v| v.as_array()) {
            if inc.iter().any(|u| u.as_str() == Some("All")) {
                parts.push("All users".to_string());
            }
        }
        if let Some(roles) = users.get("includeRoles").and_then(|v| v.as_array()) {
            if !roles.is_empty() {
                parts.push(format!("{} admin roles", roles.len()));
            }
        }
    }
    
    if let Some(apps) = conditions.get("applications") {
        if let Some(inc) = apps.get("includeApplications").and_then(|v| v.as_array()) {
            if inc.iter().any(|a| a.as_str() == Some("All")) {
                parts.push("All apps".to_string());
            } else if inc.iter().any(|a| a.as_str() == Some("Office365")) {
                parts.push("Office 365".to_string());
            }
        }
    }
    
    if !parts.is_empty() {
        println!("   Conditions: {}", parts.join(", ").dimmed());
    }
}

/// Print grant controls summary (for verbose mode)
fn print_grant_controls_summary(grant_controls: &serde_json::Value) {
    if let Some(controls) = grant_controls.get("builtInControls").and_then(|v| v.as_array()) {
        let control_names: Vec<&str> = controls.iter()
            .filter_map(|c| c.as_str())
            .map(|c| match c {
                "mfa" => "MFA",
                "compliantDevice" => "Compliant device",
                "domainJoinedDevice" => "Hybrid join",
                "block" => "BLOCK",
                _ => c,
            })
            .collect();
        if !control_names.is_empty() {
            println!("   Controls: {}", control_names.join(", ").dimmed());
        }
    }
}

// ============================================================================
// Enable / Disable Commands
// ============================================================================

#[derive(Args, Debug)]
pub struct EnableArgs {
    /// Policy ID to enable (or "all" to enable all report-only policies)
    #[arg(long, value_name = "ID")]
    pub policy: Option<String>,

    /// Policy name to enable (fuzzy match)
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// Enable all report-only policies
    #[arg(long)]
    pub all_report_only: bool,

    /// Dry run - show what would be enabled without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct DisableArgs {
    /// Policy ID to disable
    #[arg(long, value_name = "ID")]
    pub policy: Option<String>,

    /// Policy name to disable (fuzzy match)
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// Dry run - show what would be disabled without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

/// Enable one or more CA policies (move from report-only to enforced)
pub async fn enable(args: EnableArgs) -> Result<()> {
    println!(
        "{} CA policies...",
        "Enabling".cyan().bold()
    );

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    println!("→ Active tenant: {}", active_tenant.name.cyan().bold());

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Get all policies
    let policies = conditional_access::list_policies_typed(&graph).await?;

    if policies.is_empty() {
        println!("\n{} No CA policies found in tenant", "ℹ".yellow());
        return Ok(());
    }

    // Determine which policies to enable
    let policies_to_enable: Vec<_> = if args.all_report_only {
        policies
            .iter()
            .filter(|p| p.state == "enabledForReportingButNotEnforced")
            .collect()
    } else if let Some(policy_id) = &args.policy {
        policies.iter().filter(|p| p.id == *policy_id).collect()
    } else if let Some(name_pattern) = &args.name {
        let pattern_lower = name_pattern.to_lowercase();
        policies
            .iter()
            .filter(|p| p.display_name.to_lowercase().contains(&pattern_lower))
            .collect()
    } else {
        // No filter specified - show report-only policies and prompt
        let report_only: Vec<_> = policies
            .iter()
            .filter(|p| p.state == "enabledForReportingButNotEnforced")
            .collect();

        if report_only.is_empty() {
            println!("\n{} No report-only policies found to enable", "ℹ".yellow());
            println!("   All CA policies are either enabled or disabled.");
            return Ok(());
        }

        println!("\n{} Report-only policies that can be enabled:\n", "→".cyan());
        for (i, p) in report_only.iter().enumerate() {
            println!(
                "  {}. {} [{}]",
                i + 1,
                p.display_name.cyan(),
                p.id.dimmed()
            );
        }

        println!("\n{} Use --policy <ID> or --name <NAME> to enable specific policies", "ℹ".yellow());
        println!("   Use --all-report-only to enable all report-only policies");
        return Ok(());
    };

    if policies_to_enable.is_empty() {
        if let Some(name_pattern) = &args.name {
            println!("\n{} No policies found matching '{}'", "✗".red(), name_pattern);
        } else if let Some(policy_id) = &args.policy {
            println!("\n{} No policy found with ID '{}'", "✗".red(), policy_id);
        }
        return Ok(());
    }

    // Display what will be enabled
    println!("\n{} {} policies to enable:\n", "→".cyan(), policies_to_enable.len());
    for p in &policies_to_enable {
        let current_state = match p.state.as_str() {
            "enabled" => "already enabled".green(),
            "enabledForReportingButNotEnforced" => "report-only".yellow(),
            "disabled" => "disabled".red(),
            _ => p.state.as_str().into(),
        };
        println!("  • {} [{}]", p.display_name, current_state);
    }

    // Check if any are already enabled
    let already_enabled = policies_to_enable
        .iter()
        .filter(|p| p.state == "enabled")
        .count();
    
    if already_enabled == policies_to_enable.len() {
        println!("\n{} All selected policies are already enabled", "ℹ".yellow());
        return Ok(());
    }

    // Dry run
    if args.dry_run {
        println!("\n{}", "DRY RUN - No changes will be made".yellow().bold());
        return Ok(());
    }

    // Confirmation
    if !args.yes {
        use std::io::{self, Write};
        println!(
            "\n{} This will ENABLE {} CA policies (making them ENFORCED)",
            "⚠".yellow().bold(),
            policies_to_enable.len() - already_enabled
        );
        println!(
            "   {}",
            "Users will be blocked if they don't meet policy requirements!".red()
        );
        print!("\nContinue? [y/N]: ");
        io::stdout().flush()?;

        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        if !response.trim().eq_ignore_ascii_case("y") {
            println!("{}", "Cancelled.".yellow());
            return Ok(());
        }
    }

    // Enable policies
    println!("\n{} Enabling policies...\n", "→".cyan().bold());
    let mut enabled_count = 0;

    for policy in &policies_to_enable {
        if policy.state == "enabled" {
            println!("  {} {} (already enabled)", "ℹ".yellow(), policy.display_name);
            continue;
        }

        match conditional_access::enable_policy(&graph, &policy.id).await {
            Ok(_) => {
                println!("  {} {}", "✓".green(), policy.display_name);
                change_tracker::record_setting_change(
                    "Conditional Access",
                    &policy.display_name,
                    Some("report-only"),
                    "enabled",
                    &active_tenant.name,
                );
                enabled_count += 1;
            }
            Err(e) => {
                println!("  {} {} - {}", "✗".red(), policy.display_name, e);
                change_tracker::record_error(
                    "Conditional Access",
                    &policy.display_name,
                    &e.to_string(),
                    &active_tenant.name,
                );
            }
        }
    }

    println!(
        "\n{} Enabled {} CA policies",
        "✓".green().bold(),
        enabled_count
    );
    
    if enabled_count > 0 {
        println!(
            "\n{} Monitor sign-in logs in Azure Portal for any access issues",
            "ℹ".cyan()
        );
    }

    Ok(())
}

/// Disable one or more CA policies
pub async fn disable(args: DisableArgs) -> Result<()> {
    println!(
        "{} CA policies...",
        "Disabling".cyan().bold()
    );

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    println!("→ Active tenant: {}", active_tenant.name.cyan().bold());

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Get all policies
    let policies = conditional_access::list_policies_typed(&graph).await?;

    if policies.is_empty() {
        println!("\n{} No CA policies found in tenant", "ℹ".yellow());
        return Ok(());
    }

    // Determine which policies to disable
    let policies_to_disable: Vec<_> = if let Some(policy_id) = &args.policy {
        policies.iter().filter(|p| p.id == *policy_id).collect()
    } else if let Some(name_pattern) = &args.name {
        let pattern_lower = name_pattern.to_lowercase();
        policies
            .iter()
            .filter(|p| p.display_name.to_lowercase().contains(&pattern_lower))
            .collect()
    } else {
        // No filter specified - show enabled policies
        let enabled: Vec<_> = policies
            .iter()
            .filter(|p| p.state == "enabled" || p.state == "enabledForReportingButNotEnforced")
            .collect();

        if enabled.is_empty() {
            println!("\n{} No enabled policies found to disable", "ℹ".yellow());
            return Ok(());
        }

        println!("\n{} Policies that can be disabled:\n", "→".cyan());
        for (i, p) in enabled.iter().enumerate() {
            let state = if p.state == "enabled" {
                "enabled".green()
            } else {
                "report-only".yellow()
            };
            println!(
                "  {}. {} [{}] ({})",
                i + 1,
                p.display_name,
                p.id.dimmed(),
                state
            );
        }

        println!("\n{} Use --policy <ID> or --name <NAME> to disable specific policies", "ℹ".yellow());
        return Ok(());
    };

    if policies_to_disable.is_empty() {
        if let Some(name_pattern) = &args.name {
            println!("\n{} No policies found matching '{}'", "✗".red(), name_pattern);
        } else if let Some(policy_id) = &args.policy {
            println!("\n{} No policy found with ID '{}'", "✗".red(), policy_id);
        }
        return Ok(());
    }

    // Display what will be disabled
    println!("\n{} {} policies to disable:\n", "→".cyan(), policies_to_disable.len());
    for p in &policies_to_disable {
        println!("  • {}", p.display_name);
    }

    // Check if any are already disabled
    let already_disabled = policies_to_disable
        .iter()
        .filter(|p| p.state == "disabled")
        .count();
    
    if already_disabled == policies_to_disable.len() {
        println!("\n{} All selected policies are already disabled", "ℹ".yellow());
        return Ok(());
    }

    // Dry run
    if args.dry_run {
        println!("\n{}", "DRY RUN - No changes will be made".yellow().bold());
        return Ok(());
    }

    // Confirmation
    if !args.yes {
        use std::io::{self, Write};
        println!(
            "\n{} This will DISABLE {} CA policies",
            "⚠".yellow().bold(),
            policies_to_disable.len() - already_disabled
        );
        print!("\nContinue? [y/N]: ");
        io::stdout().flush()?;

        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        if !response.trim().eq_ignore_ascii_case("y") {
            println!("{}", "Cancelled.".yellow());
            return Ok(());
        }
    }

    // Disable policies
    println!("\n{} Disabling policies...\n", "→".cyan().bold());
    let mut disabled_count = 0;

    for policy in &policies_to_disable {
        if policy.state == "disabled" {
            println!("  {} {} (already disabled)", "ℹ".yellow(), policy.display_name);
            continue;
        }

        match conditional_access::disable_policy(&graph, &policy.id).await {
            Ok(_) => {
                println!("  {} {}", "✓".green(), policy.display_name);
                change_tracker::record_setting_change(
                    "Conditional Access",
                    &policy.display_name,
                    Some(&policy.state),
                    "disabled",
                    &active_tenant.name,
                );
                disabled_count += 1;
            }
            Err(e) => {
                println!("  {} {} - {}", "✗".red(), policy.display_name, e);
                change_tracker::record_error(
                    "Conditional Access",
                    &policy.display_name,
                    &e.to_string(),
                    &active_tenant.name,
                );
            }
        }
    }

    println!(
        "\n{} Disabled {} CA policies",
        "✓".green().bold(),
        disabled_count
    );

    Ok(())
}
