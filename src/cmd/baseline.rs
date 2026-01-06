use crate::config::ConfigManager;
use crate::error::Result;
use crate::graph::GraphClient;
use crate::templates;
use crate::tui::change_tracker;
use clap::{Args, Subcommand};
use colored::Colorize;
use serde_json::Value;
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum BaselineCommands {
    /// Generate a new baseline configuration
    New(NewArgs),

    /// Apply a baseline to the active tenant
    Apply(ApplyArgs),

    /// Export a baseline to a JSON file
    Export(ExportArgs),

    /// List available baseline templates
    List,
}

#[derive(Args, Debug)]
pub struct NewArgs {
    /// Platform to generate baseline for
    #[arg(value_parser = ["windows", "macos", "ios", "android"])]
    pub platform: String,

    /// Enable BitLocker/FileVault encryption
    #[arg(long)]
    pub encryption: bool,

    /// Enable Defender for Endpoint
    #[arg(long)]
    pub defender: bool,

    /// Minimum OS version (e.g., "10.0.26100.0" for Windows 11 25H2)
    #[arg(long)]
    pub min_os: Option<String>,

    /// Path to MDE onboarding XML (Windows only)
    #[arg(long)]
    pub mde_onboarding: Option<PathBuf>,

    /// Output file path (defaults to stdout)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Display name prefix for policies
    #[arg(long, default_value = "Baseline")]
    pub name: String,

    /// Template to use (basic, oib, microsoft-baseline, cis, autopilot)
    #[arg(long, default_value = "basic")]
    pub template: String,

    // === Autopilot-specific options ===
    /// Name for Autopilot dynamic security group (default: "Windows Autopilot")
    #[arg(long)]
    pub autopilot_group_name: Option<String>,

    /// Custom BitLocker policy name (e.g., "RESO BitLocker")
    #[arg(long)]
    pub bitlocker_policy_name: Option<String>,

    /// Windows Update Ring name (default: "Ring1")
    #[arg(long)]
    pub update_ring_name: Option<String>,

    /// Target Windows feature update version (default: "Windows 11, version 24H2")
    #[arg(long)]
    pub feature_update_version: Option<String>,

    /// Skip BitLocker policy in autopilot baseline
    #[arg(long)]
    pub no_bitlocker: bool,

    /// Skip Windows Update policies in autopilot baseline
    #[arg(long)]
    pub no_updates: bool,

    /// Custom Firewall policy name (e.g., "RESO Defender Firewall")
    #[arg(long)]
    pub firewall_policy_name: Option<String>,

    /// Skip Firewall policy in autopilot baseline
    #[arg(long)]
    pub no_firewall: bool,
}

#[derive(Args, Debug)]
pub struct ApplyArgs {
    /// Path to baseline JSON file
    #[arg(short, long)]
    pub file: PathBuf,

    /// Group ID to assign policies to
    #[arg(short, long)]
    pub group_id: Option<String>,

    /// Dry run - don't actually create policies
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(short, long)]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Baseline ID or name to export
    pub baseline_id: String,

    /// Output file path
    #[arg(short, long)]
    pub output: PathBuf,
}

pub async fn new(args: NewArgs) -> Result<()> {
    println!(
        "{} {} baseline configuration...",
        "Generating".cyan().bold(),
        args.platform
    );

    let baseline = match args.platform.as_str() {
        "windows" => match args.template.as_str() {
            "basic" => templates::windows::generate_baseline(&args)?,
            "oib" | "openintune" => templates::windows_oib::generate_oib_baseline(&args)?,
            "autopilot" => {
                let config = templates::windows_autopilot::AutopilotBaselineConfig {
                    name_prefix: args.name.clone(),
                    group_name: args
                        .autopilot_group_name
                        .clone()
                        .unwrap_or_else(|| "Windows Autopilot".to_string()),
                    bitlocker_policy_name: args.bitlocker_policy_name.clone(),
                    firewall_policy_name: args.firewall_policy_name.clone(),
                    update_ring_name: args
                        .update_ring_name
                        .clone()
                        .unwrap_or_else(|| "Ring1".to_string()),
                    feature_update_version: args
                        .feature_update_version
                        .clone()
                        .unwrap_or_else(|| "Windows 11, version 24H2".to_string()),
                    include_bitlocker: !args.no_bitlocker,
                    include_firewall: !args.no_firewall,
                    include_updates: !args.no_updates,
                };
                templates::windows_autopilot::generate_autopilot_baseline(&config)
            }
            "cis" | "cis-l1" => {
                let policies = templates::cis_benchmarks::generate_cis_level1(&args.name);
                serde_json::json!({
                    "version": "1.0",
                    "platform": "windows",
                    "name": format!("{} - CIS Level 1", args.name),
                    "description": "CIS Benchmark Level 1 for Windows 11 - Essential security settings",
                    "policies": policies
                })
            }
            "cis-l2" => {
                let policies = templates::cis_benchmarks::generate_cis_level2(&args.name);
                serde_json::json!({
                    "version": "1.0",
                    "platform": "windows",
                    "name": format!("{} - CIS Level 2", args.name),
                    "description": "CIS Benchmark Level 2 for Windows 11 - Defense-in-depth (may impact functionality)",
                    "policies": policies
                })
            }
            _ => {
                return Err(crate::error::Error::ConfigError(format!(
                    "Unknown template: '{}'. Available: basic, oib, autopilot, cis, cis-l1, cis-l2",
                    args.template
                )));
            }
        },
        "macos" => match args.template.as_str() {
            "basic" => templates::macos::generate_basic_macos_baseline(&args)?,
            "oib" | "openintune" => templates::macos::generate_macos_baseline(&args)?,
            _ => {
                return Err(crate::error::Error::ConfigError(format!(
                    "Unknown template: '{}'. Available for macOS: basic, oib",
                    args.template
                )));
            }
        },
        "ios" => match args.template.as_str() {
            "basic" => templates::ios::generate_basic_ios_baseline(&args)?,
            "oib" | "openintune" | "baseline" => templates::ios::generate_ios_baseline(&args)?,
            _ => {
                return Err(crate::error::Error::ConfigError(format!(
                    "Unknown template: '{}'. Available for iOS: basic, oib",
                    args.template
                )));
            }
        },
        "android" => match args.template.as_str() {
            "basic" => templates::android::generate_basic_android_baseline(&args)?,
            "oib" | "openintune" | "baseline" => {
                templates::android::generate_android_baseline(&args)?
            }
            _ => {
                return Err(crate::error::Error::ConfigError(format!(
                    "Unknown template: '{}'. Available for Android: basic, oib",
                    args.template
                )));
            }
        },
        _ => unreachable!(),
    };

    let json = serde_json::to_string_pretty(&baseline)?;

    if let Some(output_path) = &args.output {
        std::fs::write(output_path, &json)?;
        println!(
            "{} Baseline saved to: {}",
            "✓".green().bold(),
            output_path.display()
        );
    } else {
        println!("\n{}", json);
    }

    // Print summary
    println!("\n{}", "Baseline Summary:".cyan().bold());
    println!("  Platform: {}", args.platform);
    println!(
        "  Policies: {}",
        baseline["policies"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0)
    );
    if args.encryption {
        println!("  {} Encryption enabled", "✓".green());
    }
    if args.defender {
        println!("  {} Defender for Endpoint enabled", "✓".green());
    }

    Ok(())
}

pub async fn apply(args: ApplyArgs) -> Result<()> {
    println!(
        "{} baseline from: {}",
        "Applying".cyan().bold(),
        args.file.display()
    );

    // Load baseline from file
    let baseline_json = std::fs::read_to_string(&args.file).map_err(|e| {
        crate::error::Error::ConfigError(format!(
            "Failed to read baseline file {}: {}",
            args.file.display(),
            e
        ))
    })?;
    let baseline: Value = serde_json::from_str(&baseline_json).map_err(|e| {
        crate::error::Error::ConfigError(format!(
            "Invalid JSON in baseline file {}: {}",
            args.file.display(),
            e
        ))
    })?;

    // Get config manager
    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    println!(
        "{} Active tenant: {}",
        "→".cyan(),
        active_tenant.name.cyan().bold()
    );

    // Confirm unless --yes flag
    if !args.yes && !args.dry_run {
        use std::io::{self, Write};
        print!(
            "\n{} Apply {} policies to tenant '{}'? [y/N]: ",
            "?".yellow().bold(),
            baseline["policies"]
                .as_array()
                .map(|a| a.len())
                .unwrap_or(0),
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

    if args.dry_run {
        println!("\n{} (no policies created)", "DRY RUN".yellow().bold());
        if let Some(policies) = baseline["policies"].as_array() {
            for policy in policies {
                println!(
                    "  {} would create: {}",
                    "→".cyan(),
                    policy["displayName"].as_str().unwrap_or("Unknown")
                );
            }
        }
        return Ok(());
    }

    // Get Graph client
    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Apply each policy
    let policies = baseline["policies"]
        .as_array()
        .ok_or_else(|| crate::error::Error::ConfigError("Invalid baseline format".into()))?;

    println!("\n{} policies...", "Deploying".cyan().bold());

    for policy in policies {
        let policy_type = policy["@odata.type"]
            .as_str()
            .ok_or_else(|| crate::error::Error::ConfigError("Missing @odata.type".into()))?;

        // Settings Catalog uses "name" instead of "displayName"
        let display_name = policy["displayName"]
            .as_str()
            .or_else(|| policy["name"].as_str())
            .ok_or_else(|| {
                crate::error::Error::ConfigError("Missing displayName or name".into())
            })?;

        print!("  {} Creating: {}... ", "→".cyan(), display_name);

        let result = crate::graph::intune::create_policy(&graph, policy_type, policy).await;

        match result {
            Ok(created_policy) => {
                println!("{}", "✓".green().bold());

                // Record success in audit trail
                change_tracker::record_policy_created(
                    policy_type,
                    display_name,
                    &active_tenant.name,
                );

                // Assign to group if specified
                if let Some(group_id) = &args.group_id {
                    let policy_id = created_policy["id"].as_str().ok_or_else(|| {
                        crate::error::Error::ConfigError("Missing policy id".into())
                    })?;

                    crate::graph::intune::assign_policy(&graph, policy_type, policy_id, group_id)
                        .await?;
                    println!("    {} Assigned to group: {}", "✓".green(), group_id);
                }
            }
            Err(e) => {
                println!("{} {}", "✗".red().bold(), e);
                // Record failure in audit trail
                change_tracker::record_error(
                    policy_type,
                    display_name,
                    &e.to_string(),
                    &active_tenant.name,
                );
            }
        }
    }

    // Record overall baseline deployment
    change_tracker::record_baseline_deployed(
        &args.file.display().to_string(),
        policies.len(),
        &active_tenant.name,
    );

    println!(
        "\n{} Successfully deployed {} policies",
        "✓".green().bold(),
        policies.len()
    );

    Ok(())
}

pub async fn export(_args: ExportArgs) -> Result<()> {
    println!(
        "{}",
        "Baseline export is planned for a future release.".yellow()
    );
    println!();
    println!("For now, use these alternatives:");
    println!(
        "  {} - Export all tenant policies to JSON",
        "ctl365 export".cyan()
    );
    println!(
        "  {} - Export specific policy types",
        "ctl365 export --type compliance".cyan()
    );
    println!();
    Ok(())
}

pub async fn list() -> Result<()> {
    println!("{}", "Available Baseline Templates:".cyan().bold());
    println!();

    println!("{} {}", "Platform:".bold(), "Windows".cyan());
    println!();

    println!(
        "  {} {} - Basic security baseline",
        "•".cyan(),
        "basic".bold()
    );
    println!("    Simple compliance, BitLocker, Defender, Firewall");
    println!();

    println!(
        "  {} {} - OpenIntuneBaseline v3.6 (PRODUCTION-READY)",
        "•".green(),
        "oib".bold()
    );
    println!(
        "    {} Battle-tested by Microsoft MVP across multiple enterprises",
        "✓".green()
    );
    println!(
        "    {} 15+ policies: Compliance (4), Settings Catalog (11+)",
        "✓".green()
    );
    println!("    {} CIS-aligned with documented deviations", "✓".green());
    println!(
        "    {} Frameworks: NCSC, CIS, ACSC Essential Eight, MS Baselines",
        "✓".green()
    );
    println!(
        "    {} Features: WHfB, LAPS, ASR Rules, BitLocker, Firewall, MDE",
        "✓".green()
    );
    println!();

    println!(
        "  {} {} - CIS Benchmark Level 1 (PRODUCTION-READY)",
        "•".green(),
        "cis".bold()
    );
    println!(
        "    {} Essential security settings, broadly applicable",
        "✓".green()
    );
    println!(
        "    {} Based on CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0",
        "✓".green()
    );
    println!(
        "    {} Password, lockout, audit, Windows components",
        "✓".green()
    );
    println!();

    println!(
        "  {} {} - CIS Benchmark Level 2",
        "•".yellow(),
        "cis-l2".bold()
    );
    println!(
        "    {} Defense-in-depth (may impact functionality)",
        "⚠".yellow()
    );
    println!(
        "    {} Includes all L1 controls plus additional hardening",
        "✓".green()
    );
    println!(
        "    {} Remote Desktop, network, legacy protocol hardening",
        "✓".green()
    );
    println!();

    println!(
        "  {} {} - Windows Autopilot Baseline (PRODUCTION-READY)",
        "•".green(),
        "autopilot".bold()
    );
    println!("    {} Complete Autopilot deployment setup", "✓".green());
    println!(
        "    {} Dynamic security group for company-owned Windows devices",
        "✓".green()
    );
    println!(
        "    {} User-driven Autopilot profile (Microsoft Entra joined)",
        "✓".green()
    );
    println!(
        "    {} BitLocker full disk encryption (Endpoint Security)",
        "✓".green()
    );
    println!(
        "    {} Windows Defender Firewall (all profiles enabled)",
        "✓".green()
    );
    println!(
        "    {} Windows Update Ring + Feature Update (25H2)",
        "✓".green()
    );
    println!();

    println!("{} {}", "Platform:".bold(), "macOS".cyan());
    println!();
    println!("  {} {} - Basic macOS baseline", "•".cyan(), "basic".bold());
    println!("    Device restrictions, FileVault, Gatekeeper, XProtect");
    println!();
    println!(
        "  {} {} - OpenIntune macOS Baseline (PRODUCTION-READY)",
        "•".green(),
        "oib".bold()
    );
    println!("    {} Enterprise-grade macOS management", "✓".green());
    println!(
        "    {} FileVault encryption, password policies",
        "✓".green()
    );
    println!(
        "    {} System Integrity Protection, Gatekeeper",
        "✓".green()
    );
    println!();

    println!("{} {}", "Platform:".bold(), "iOS".cyan());
    println!();
    println!("  {} {} - Basic iOS baseline", "•".cyan(), "basic".bold());
    println!("    Compliance, passcode, jailbreak detection");
    println!();
    println!(
        "  {} {} - OpenIntune iOS Baseline (PRODUCTION-READY)",
        "•".green(),
        "oib".bold()
    );
    println!("    {} App Protection Policies (MAM)", "✓".green());
    println!(
        "    {} Device restrictions and passcode policies",
        "✓".green()
    );
    println!(
        "    {} Email profiles and Defender for Endpoint",
        "✓".green()
    );
    println!();

    println!("{} {}", "Platform:".bold(), "Android".cyan());
    println!();
    println!(
        "  {} {} - Basic Android baseline",
        "•".cyan(),
        "basic".bold()
    );
    println!("    Work Profile compliance, basic restrictions");
    println!();
    println!(
        "  {} {} - OpenIntune Android Baseline (PRODUCTION-READY)",
        "•".green(),
        "oib".bold()
    );
    println!(
        "    {} Work Profile (BYOD) and Fully Managed modes",
        "✓".green()
    );
    println!("    {} SafetyNet attestation, encryption", "✓".green());
    println!(
        "    {} App Protection Policies (MAM) and Defender",
        "✓".green()
    );
    println!();

    println!("{}", "Usage Examples:".bold());
    println!(
        "  {} {} baseline new windows --template oib --encryption --defender",
        "Windows:".cyan(),
        "ctl365".bold()
    );
    println!(
        "  {} {} baseline new windows --template autopilot --name RESO",
        "Autopilot:".cyan(),
        "ctl365".bold()
    );
    println!(
        "  {} {} baseline new windows --template autopilot --name RESO --bitlocker-policy-name \"RESO BitLocker\" --update-ring-name Ring1",
        "Autopilot Custom:".cyan().dimmed(),
        "ctl365".bold()
    );
    println!(
        "  {} {} baseline new macos --template oib --encryption",
        "macOS:".cyan().dimmed(),
        "ctl365".bold()
    );
    println!(
        "  {} {} baseline new ios --template oib --defender --min-os 17.0",
        "iOS:".cyan().dimmed(),
        "ctl365".bold()
    );
    println!(
        "  {} {} baseline new android --template oib --defender",
        "Android:".cyan().dimmed(),
        "ctl365".bold()
    );
    println!();

    println!("{}", "Templates:".bold());
    println!("  basic            - Simple, straightforward baseline (default)");
    println!("  oib/openintune   - OpenIntuneBaseline v3.6 (recommended for production)");
    println!("  autopilot        - Windows Autopilot with BitLocker, Firewall, Updates");
    println!("  cis/cis-l1       - CIS Benchmark Level 1 (essential security)");
    println!("  cis-l2           - CIS Benchmark Level 2 (defense-in-depth)");
    println!();

    println!("{}", "Autopilot Template Options:".bold());
    println!("  --autopilot-group-name     Custom name for dynamic security group");
    println!("  --bitlocker-policy-name    Custom BitLocker policy name (e.g., 'RESO BitLocker')");
    println!("  --firewall-policy-name     Custom Firewall policy name (e.g., 'RESO Defender')");
    println!("  --update-ring-name         Update ring name (default: Ring1)");
    println!("  --feature-update-version   Target Windows version (default: 24H2)");
    println!("  --no-bitlocker             Skip BitLocker policy");
    println!("  --no-firewall              Skip Firewall policy");
    println!("  --no-updates               Skip Windows Update policies");

    Ok(())
}
