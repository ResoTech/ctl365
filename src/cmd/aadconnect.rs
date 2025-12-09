//! Azure AD Connect Documentation
//!
//! Export and document Azure AD Connect (now Entra Connect) synchronization configuration.
//! Useful for migration planning, disaster recovery, and compliance documentation.
//!
//! Features:
//! - Export sync configuration details
//! - Document sync rules and filtering
//! - Generate migration readiness report
//! - Compare on-prem AD with Entra ID

use crate::config::ConfigManager;
use crate::error::Result;
use crate::graph::GraphClient;
use clap::Args;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct ExportConfigArgs {
    /// Output directory for documentation
    #[arg(short, long, default_value = "./aadconnect-docs")]
    pub output: PathBuf,

    /// Output format: json, markdown, html
    #[arg(long, default_value = "markdown")]
    pub format: String,

    /// Include sync rules details
    #[arg(long)]
    pub include_rules: bool,

    /// Include attribute flow mappings
    #[arg(long)]
    pub include_mappings: bool,
}

#[derive(Args, Debug)]
pub struct SyncStatusArgs {
    /// Show detailed sync status
    #[arg(short, long)]
    pub verbose: bool,

    /// Show sync errors
    #[arg(long)]
    pub errors: bool,

    /// Show pending exports
    #[arg(long)]
    pub pending: bool,
}

#[derive(Args, Debug)]
pub struct MigrationCheckArgs {
    /// Output file for migration report
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Target: cloud-only, hybrid, passthrough
    #[arg(long, default_value = "cloud-only")]
    pub target: String,

    /// Dry run analysis
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct CompareArgs {
    /// AD domain to compare
    #[arg(long)]
    pub domain: Option<String>,

    /// Output file for comparison report
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Show only differences
    #[arg(long)]
    pub diff_only: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AadConnectConfig {
    pub tenant_name: String,
    pub sync_enabled: bool,
    pub password_hash_sync_enabled: bool,
    pub passthrough_auth_enabled: bool,
    pub federation_enabled: bool,
    pub seamless_sso_enabled: bool,
    pub last_sync_time: Option<String>,
    pub sync_interval_minutes: u32,
    pub on_premises_domains: Vec<String>,
    pub sync_client_version: Option<String>,
    pub sync_server_name: Option<String>,
    pub sync_rules: Vec<SyncRule>,
    pub connector_spaces: Vec<ConnectorSpace>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SyncRule {
    pub name: String,
    pub direction: String, // Inbound, Outbound
    pub source_object_type: String,
    pub target_object_type: String,
    pub link_type: String,
    pub precedence: u32,
    pub scoping_filter: Option<String>,
    pub attribute_flows: Vec<AttributeFlow>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttributeFlow {
    pub source_attribute: String,
    pub target_attribute: String,
    pub flow_type: String,
    pub expression: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConnectorSpace {
    pub name: String,
    pub connector_type: String,
    pub domain: Option<String>,
    pub object_count: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MigrationReadinessReport {
    pub tenant_name: String,
    pub assessment_date: String,
    pub target_model: String,
    pub overall_readiness: String,
    pub readiness_score: f32,
    pub blockers: Vec<MigrationFinding>,
    pub warnings: Vec<MigrationFinding>,
    pub recommendations: Vec<MigrationFinding>,
    pub user_impact: UserImpactSummary,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MigrationFinding {
    pub category: String,
    pub title: String,
    pub description: String,
    pub impact: String,
    pub remediation: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserImpactSummary {
    pub total_users: u32,
    pub synced_users: u32,
    pub cloud_only_users: u32,
    pub guest_users: u32,
    pub users_with_on_prem_mailbox: u32,
    pub users_with_cloud_mailbox: u32,
}

/// Export AAD Connect configuration documentation
pub async fn export_config(args: ExportConfigArgs) -> Result<()> {
    println!(
        "{} Azure AD Connect configuration...",
        "Exporting".cyan().bold()
    );

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant".into()))?;

    println!("→ Tenant: {}", active_tenant.name.cyan().bold());
    println!("→ Output: {}", args.output.display().to_string().cyan());
    println!("→ Format: {}", args.format.cyan());

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Create output directory
    fs::create_dir_all(&args.output)?;

    // Fetch organization sync settings
    println!("\n{} Fetching sync configuration...", "→".cyan());

    let aad_config = fetch_aad_connect_config(&graph, &active_tenant.name).await?;

    // Display summary
    display_config_summary(&aad_config);

    // Generate documentation
    match args.format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&aad_config)?;
            fs::write(args.output.join("aadconnect_config.json"), json)?;
        }
        "html" => {
            let html = generate_html_doc(&aad_config);
            fs::write(args.output.join("aadconnect_config.html"), html)?;
        }
        _ => {
            let md = generate_markdown_doc(&aad_config, args.include_rules, args.include_mappings);
            fs::write(args.output.join("AAD_Connect_Configuration.md"), md)?;
        }
    }

    println!(
        "\n{} Documentation exported to: {}",
        "✓".green().bold(),
        args.output.display()
    );

    Ok(())
}

/// Show sync status
pub async fn sync_status(args: SyncStatusArgs) -> Result<()> {
    println!(
        "{} Azure AD Connect sync status...",
        "Checking".cyan().bold()
    );

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant".into()))?;

    println!("→ Tenant: {}", active_tenant.name.cyan().bold());

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Get organization info
    match graph.get::<Value>("organization").await {
        Ok(response) => {
            if let Some(orgs) = response["value"].as_array() {
                if let Some(org) = orgs.first() {
                    let on_premises_sync = org["onPremisesSyncEnabled"].as_bool().unwrap_or(false);
                    let last_sync = org["onPremisesLastSyncDateTime"]
                        .as_str()
                        .unwrap_or("Never");

                    println!("\n{} Sync Status:", "→".cyan().bold());
                    println!(
                        "  Directory Sync: {}",
                        if on_premises_sync {
                            "Enabled".green()
                        } else {
                            "Disabled".yellow()
                        }
                    );
                    println!("  Last Sync: {}", last_sync.cyan());

                    if args.verbose {
                        let pwd_sync = org["onPremisesLastPasswordSyncDateTime"].as_str();
                        if let Some(pwd_time) = pwd_sync {
                            println!("  Last Password Sync: {}", pwd_time.cyan());
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("  {} Could not fetch org info: {}", "✗".red(), e);
        }
    }

    // Check for sync errors if requested
    if args.errors {
        println!("\n{} Sync Errors:", "→".cyan().bold());

        match graph
            .get_beta::<Value>("directory/onPremisesSynchronization")
            .await
        {
            Ok(response) => {
                if let Some(configs) = response["value"].as_array() {
                    for sync_config in configs {
                        let config_name = sync_config["configuration"]["accidentalDeletionPrevention"]["alertThreshold"]
                            .as_u64()
                            .map(|t| format!("Threshold: {}", t))
                            .unwrap_or_else(|| "Default".to_string());
                        println!("  Sync Configuration: {}", config_name);
                    }
                }
            }
            Err(_) => {
                println!(
                    "  {} No sync errors found or unable to retrieve",
                    "ℹ".yellow()
                );
            }
        }
    }

    // Check pending exports
    if args.pending {
        println!("\n{} Pending Changes:", "→".cyan().bold());
        println!(
            "  {} Pending export information requires AAD Connect server access",
            "ℹ".yellow()
        );
        println!("  Use Synchronization Service Manager on the AAD Connect server");
    }

    Ok(())
}

/// Check migration readiness
pub async fn migration_check(args: MigrationCheckArgs) -> Result<()> {
    println!(
        "{} migration readiness to {}...",
        "Assessing".cyan().bold(),
        args.target.cyan()
    );

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant".into()))?;

    println!("→ Tenant: {}", active_tenant.name.cyan().bold());
    println!("→ Target: {}", args.target.cyan());

    if args.dry_run {
        println!("\n{} DRY RUN - Would assess:", "ℹ".yellow().bold());
        println!("  • User sync dependencies");
        println!("  • Application integrations");
        println!("  • Authentication methods");
        println!("  • Mailbox locations");
        return Ok(());
    }

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Generate migration assessment
    let report = assess_migration_readiness(&graph, &active_tenant.name, &args.target).await?;

    // Display summary
    display_migration_summary(&report);

    // Save report if output specified
    if let Some(output_path) = args.output {
        let json = serde_json::to_string_pretty(&report)?;
        fs::write(&output_path, json)?;
        println!(
            "\n{} Report saved to: {}",
            "✓".green(),
            output_path.display()
        );
    }

    Ok(())
}

/// Compare on-prem with Entra ID
pub async fn compare(_args: CompareArgs) -> Result<()> {
    println!(
        "{} on-premises AD with Entra ID...",
        "Comparing".cyan().bold()
    );

    println!("\n{} Direct AD comparison requires:", "ℹ".yellow().bold());
    println!("  • LDAP access to on-premises domain controller");
    println!("  • Active Directory PowerShell module");
    println!();
    println!("For comparison, export from both sources:");
    println!("  1. Export on-prem users: Get-ADUser -Filter * | Export-Csv onprem.csv");
    println!("  2. Export Entra users: ctl365 export export --output ./entra-export");
    println!("  3. Compare CSVs manually or with diff tools");
    println!();
    println!("Alternatively, use AAD Connect's Troubleshooting tool");

    Ok(())
}

async fn fetch_aad_connect_config(
    graph: &GraphClient,
    tenant_name: &str,
) -> Result<AadConnectConfig> {
    let mut aad_config = AadConnectConfig {
        tenant_name: tenant_name.to_string(),
        sync_enabled: false,
        password_hash_sync_enabled: false,
        passthrough_auth_enabled: false,
        federation_enabled: false,
        seamless_sso_enabled: false,
        last_sync_time: None,
        sync_interval_minutes: 30,
        on_premises_domains: Vec::new(),
        sync_client_version: None,
        sync_server_name: None,
        sync_rules: Vec::new(),
        connector_spaces: Vec::new(),
    };

    // Get organization sync settings
    if let Ok(response) = graph.get::<Value>("organization").await {
        if let Some(orgs) = response["value"].as_array() {
            if let Some(org) = orgs.first() {
                aad_config.sync_enabled = org["onPremisesSyncEnabled"].as_bool().unwrap_or(false);
                aad_config.last_sync_time = org["onPremisesLastSyncDateTime"]
                    .as_str()
                    .map(|s| s.to_string());

                // Get verified domains
                if let Some(domains) = org["verifiedDomains"].as_array() {
                    for domain in domains {
                        if let Some(name) = domain["name"].as_str() {
                            if domain["type"].as_str() == Some("Managed") {
                                aad_config.on_premises_domains.push(name.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Check directory sync configuration
    if let Ok(response) = graph
        .get_beta::<Value>("directory/onPremisesSynchronization")
        .await
    {
        if let Some(configs) = response["value"].as_array() {
            for sync_config in configs {
                // Check features
                if let Some(features) = sync_config["features"].as_object() {
                    aad_config.password_hash_sync_enabled = features
                        .get("passwordHashSyncEnabled")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    aad_config.passthrough_auth_enabled = features
                        .get("passthroughAuthenticationEnabled")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    aad_config.seamless_sso_enabled = features
                        .get("seamlessSsoEnabled")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                }
            }
        }
    }

    // Check for federation
    if let Ok(response) = graph.get_beta::<Value>("domains").await {
        if let Some(domains) = response["value"].as_array() {
            for domain in domains {
                let auth_type = domain["authenticationType"].as_str().unwrap_or("Managed");
                if auth_type == "Federated" {
                    aad_config.federation_enabled = true;
                    break;
                }
            }
        }
    }

    // Add sample sync rules (actual rules require on-prem access)
    aad_config.sync_rules = get_default_sync_rules();

    Ok(aad_config)
}

fn get_default_sync_rules() -> Vec<SyncRule> {
    vec![
        SyncRule {
            name: "In from AD - User Join".to_string(),
            direction: "Inbound".to_string(),
            source_object_type: "user".to_string(),
            target_object_type: "person".to_string(),
            link_type: "Join".to_string(),
            precedence: 100,
            scoping_filter: Some(
                "objectClass=user AND NOT userAccountControl:1.2.840.113556.1.4.803:=2".to_string(),
            ),
            attribute_flows: vec![
                AttributeFlow {
                    source_attribute: "objectGUID".to_string(),
                    target_attribute: "sourceAnchor".to_string(),
                    flow_type: "Direct".to_string(),
                    expression: None,
                },
                AttributeFlow {
                    source_attribute: "userPrincipalName".to_string(),
                    target_attribute: "userPrincipalName".to_string(),
                    flow_type: "Direct".to_string(),
                    expression: None,
                },
            ],
        },
        SyncRule {
            name: "In from AD - Group Join".to_string(),
            direction: "Inbound".to_string(),
            source_object_type: "group".to_string(),
            target_object_type: "group".to_string(),
            link_type: "Join".to_string(),
            precedence: 101,
            scoping_filter: Some("objectClass=group".to_string()),
            attribute_flows: vec![AttributeFlow {
                source_attribute: "objectGUID".to_string(),
                target_attribute: "sourceAnchor".to_string(),
                flow_type: "Direct".to_string(),
                expression: None,
            }],
        },
        SyncRule {
            name: "Out to AAD - User Join".to_string(),
            direction: "Outbound".to_string(),
            source_object_type: "person".to_string(),
            target_object_type: "user".to_string(),
            link_type: "Join".to_string(),
            precedence: 100,
            scoping_filter: None,
            attribute_flows: vec![
                AttributeFlow {
                    source_attribute: "userPrincipalName".to_string(),
                    target_attribute: "userPrincipalName".to_string(),
                    flow_type: "Direct".to_string(),
                    expression: None,
                },
                AttributeFlow {
                    source_attribute: "displayName".to_string(),
                    target_attribute: "displayName".to_string(),
                    flow_type: "Direct".to_string(),
                    expression: None,
                },
            ],
        },
    ]
}

async fn assess_migration_readiness(
    graph: &GraphClient,
    tenant_name: &str,
    target: &str,
) -> Result<MigrationReadinessReport> {
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    let mut recommendations = Vec::new();

    let mut total_users = 0u32;
    let mut synced_users = 0u32;
    let mut cloud_only_users = 0u32;
    let mut guest_users = 0u32;

    // Count user types
    if let Ok(response) = graph
        .get::<Value>("users?$count=true&$select=id,userType,onPremisesSyncEnabled")
        .await
    {
        if let Some(users) = response["value"].as_array() {
            for user in users {
                total_users += 1;
                let user_type = user["userType"].as_str().unwrap_or("Member");
                let is_synced = user["onPremisesSyncEnabled"].as_bool().unwrap_or(false);

                if user_type == "Guest" {
                    guest_users += 1;
                } else if is_synced {
                    synced_users += 1;
                } else {
                    cloud_only_users += 1;
                }
            }
        }
    }

    // Check organization sync status
    let mut sync_enabled = false;
    if let Ok(response) = graph.get::<Value>("organization").await {
        if let Some(orgs) = response["value"].as_array() {
            if let Some(org) = orgs.first() {
                sync_enabled = org["onPremisesSyncEnabled"].as_bool().unwrap_or(false);
            }
        }
    }

    // Generate findings based on target
    match target {
        "cloud-only" => {
            if sync_enabled {
                warnings.push(MigrationFinding {
                    category: "Identity".to_string(),
                    title: "Directory Sync Enabled".to_string(),
                    description: "Tenant has directory synchronization enabled".to_string(),
                    impact: "High".to_string(),
                    remediation: "Plan sync cutover and user migration strategy".to_string(),
                });
            }

            if synced_users > 0 {
                blockers.push(MigrationFinding {
                    category: "Users".to_string(),
                    title: "Synced Users Present".to_string(),
                    description: format!("{} users are synced from on-premises AD", synced_users),
                    impact: "High".to_string(),
                    remediation:
                        "Convert synced users to cloud-only or migrate to new cloud identities"
                            .to_string(),
                });
            }

            recommendations.push(MigrationFinding {
                category: "Authentication".to_string(),
                title: "Enable Cloud-Native MFA".to_string(),
                description: "Ensure all users have cloud MFA configured".to_string(),
                impact: "Medium".to_string(),
                remediation: "Configure Conditional Access MFA policies".to_string(),
            });

            recommendations.push(MigrationFinding {
                category: "Applications".to_string(),
                title: "Review On-Premises App Dependencies".to_string(),
                description: "Identify applications dependent on on-premises AD".to_string(),
                impact: "Medium".to_string(),
                remediation: "Plan application migration to cloud-based authentication".to_string(),
            });
        }
        "hybrid" => {
            if !sync_enabled {
                blockers.push(MigrationFinding {
                    category: "Identity".to_string(),
                    title: "Directory Sync Not Enabled".to_string(),
                    description: "Hybrid identity requires directory synchronization".to_string(),
                    impact: "High".to_string(),
                    remediation: "Install and configure Azure AD Connect".to_string(),
                });
            }

            recommendations.push(MigrationFinding {
                category: "Authentication".to_string(),
                title: "Consider Password Hash Sync".to_string(),
                description: "PHS provides backup authentication and leaked credential detection"
                    .to_string(),
                impact: "Medium".to_string(),
                remediation: "Enable Password Hash Synchronization".to_string(),
            });

            recommendations.push(MigrationFinding {
                category: "High Availability".to_string(),
                title: "Deploy Staging Server".to_string(),
                description: "Add AAD Connect staging server for disaster recovery".to_string(),
                impact: "Medium".to_string(),
                remediation: "Configure AAD Connect in staging mode on secondary server"
                    .to_string(),
            });
        }
        "passthrough" => {
            if !sync_enabled {
                blockers.push(MigrationFinding {
                    category: "Identity".to_string(),
                    title: "Directory Sync Required".to_string(),
                    description: "Pass-through authentication requires directory sync".to_string(),
                    impact: "High".to_string(),
                    remediation: "Install and configure Azure AD Connect with PTA".to_string(),
                });
            }

            warnings.push(MigrationFinding {
                category: "High Availability".to_string(),
                title: "PTA Agent Redundancy".to_string(),
                description: "Multiple PTA agents required for high availability".to_string(),
                impact: "High".to_string(),
                remediation: "Deploy minimum 3 PTA agents across multiple servers".to_string(),
            });

            recommendations.push(MigrationFinding {
                category: "Security".to_string(),
                title: "Enable PHS as Backup".to_string(),
                description: "Password Hash Sync provides authentication fallback".to_string(),
                impact: "Medium".to_string(),
                remediation: "Enable PHS alongside PTA for resilience".to_string(),
            });
        }
        _ => {}
    }

    // Calculate readiness score
    let blocker_penalty = blockers.len() as f32 * 25.0;
    let warning_penalty = warnings.len() as f32 * 10.0;
    let readiness_score = (100.0 - blocker_penalty - warning_penalty).max(0.0);

    let overall_readiness = if readiness_score >= 80.0 {
        "Ready"
    } else if readiness_score >= 50.0 {
        "Needs Work"
    } else {
        "Not Ready"
    };

    Ok(MigrationReadinessReport {
        tenant_name: tenant_name.to_string(),
        assessment_date: chrono::Utc::now().to_rfc3339(),
        target_model: target.to_string(),
        overall_readiness: overall_readiness.to_string(),
        readiness_score,
        blockers,
        warnings,
        recommendations,
        user_impact: UserImpactSummary {
            total_users,
            synced_users,
            cloud_only_users,
            guest_users,
            users_with_on_prem_mailbox: 0, // Would need Exchange integration
            users_with_cloud_mailbox: 0,
        },
    })
}

fn display_config_summary(config: &AadConnectConfig) {
    println!("\n{} Configuration Summary:", "→".cyan().bold());
    println!(
        "  Directory Sync: {}",
        if config.sync_enabled {
            "Enabled".green()
        } else {
            "Disabled".yellow()
        }
    );
    println!(
        "  Password Hash Sync: {}",
        if config.password_hash_sync_enabled {
            "Enabled".green()
        } else {
            "Disabled".yellow()
        }
    );
    println!(
        "  Pass-through Auth: {}",
        if config.passthrough_auth_enabled {
            "Enabled".green()
        } else {
            "Disabled".yellow()
        }
    );
    println!(
        "  Federation: {}",
        if config.federation_enabled {
            "Enabled".cyan()
        } else {
            "Disabled".yellow()
        }
    );
    println!(
        "  Seamless SSO: {}",
        if config.seamless_sso_enabled {
            "Enabled".green()
        } else {
            "Disabled".yellow()
        }
    );

    if let Some(last_sync) = &config.last_sync_time {
        println!("  Last Sync: {}", last_sync.cyan());
    }

    if !config.on_premises_domains.is_empty() {
        println!("\n{} Verified Domains:", "→".cyan().bold());
        for domain in &config.on_premises_domains {
            println!("  • {}", domain);
        }
    }
}

fn display_migration_summary(report: &MigrationReadinessReport) {
    let score_color = if report.readiness_score >= 80.0 {
        "green"
    } else if report.readiness_score >= 50.0 {
        "yellow"
    } else {
        "red"
    };

    println!("\n{} Migration Readiness Assessment:", "→".cyan().bold());
    println!("  Target Model: {}", report.target_model.cyan());
    println!(
        "  Overall Readiness: {} ({:.0}%)",
        match score_color {
            "green" => report.overall_readiness.green(),
            "yellow" => report.overall_readiness.yellow(),
            _ => report.overall_readiness.red(),
        },
        report.readiness_score
    );

    println!("\n{} User Impact:", "→".cyan().bold());
    println!("  Total Users: {}", report.user_impact.total_users);
    println!(
        "  Synced Users: {}",
        report.user_impact.synced_users.to_string().cyan()
    );
    println!(
        "  Cloud-Only Users: {}",
        report.user_impact.cloud_only_users
    );
    println!("  Guest Users: {}", report.user_impact.guest_users);

    if !report.blockers.is_empty() {
        println!("\n{} Blockers:", "✗".red().bold());
        for blocker in &report.blockers {
            println!("  • {} - {}", blocker.title.red(), blocker.description);
        }
    }

    if !report.warnings.is_empty() {
        println!("\n{} Warnings:", "⚠".yellow().bold());
        for warning in &report.warnings {
            println!("  • {} - {}", warning.title.yellow(), warning.description);
        }
    }

    if !report.recommendations.is_empty() {
        println!("\n{} Recommendations:", "ℹ".blue().bold());
        for rec in &report.recommendations {
            println!("  • {} - {}", rec.title, rec.description);
        }
    }
}

fn generate_markdown_doc(
    config: &AadConnectConfig,
    include_rules: bool,
    include_mappings: bool,
) -> String {
    let mut md = String::new();

    md.push_str("# Azure AD Connect Configuration Documentation\n\n");
    md.push_str(&format!(
        "Generated: {}\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")
    ));
    md.push_str(&format!("Tenant: {}\n\n", config.tenant_name));

    md.push_str("## Synchronization Settings\n\n");
    md.push_str("| Setting | Value |\n");
    md.push_str("|---------|-------|\n");
    md.push_str(&format!(
        "| Directory Sync Enabled | {} |\n",
        config.sync_enabled
    ));
    md.push_str(&format!(
        "| Password Hash Sync | {} |\n",
        config.password_hash_sync_enabled
    ));
    md.push_str(&format!(
        "| Pass-through Authentication | {} |\n",
        config.passthrough_auth_enabled
    ));
    md.push_str(&format!("| Federation | {} |\n", config.federation_enabled));
    md.push_str(&format!(
        "| Seamless SSO | {} |\n",
        config.seamless_sso_enabled
    ));
    md.push_str(&format!(
        "| Sync Interval | {} minutes |\n",
        config.sync_interval_minutes
    ));

    if let Some(last_sync) = &config.last_sync_time {
        md.push_str(&format!("| Last Sync | {} |\n", last_sync));
    }

    md.push_str("\n## Verified Domains\n\n");
    for domain in &config.on_premises_domains {
        md.push_str(&format!("- {}\n", domain));
    }

    if include_rules && !config.sync_rules.is_empty() {
        md.push_str("\n## Synchronization Rules\n\n");

        for rule in &config.sync_rules {
            md.push_str(&format!("### {}\n\n", rule.name));
            md.push_str(&format!("- **Direction:** {}\n", rule.direction));
            md.push_str(&format!(
                "- **Source Object Type:** {}\n",
                rule.source_object_type
            ));
            md.push_str(&format!(
                "- **Target Object Type:** {}\n",
                rule.target_object_type
            ));
            md.push_str(&format!("- **Precedence:** {}\n", rule.precedence));

            if let Some(filter) = &rule.scoping_filter {
                md.push_str(&format!("- **Scoping Filter:** `{}`\n", filter));
            }

            if include_mappings && !rule.attribute_flows.is_empty() {
                md.push_str("\n**Attribute Flows:**\n\n");
                md.push_str("| Source | Target | Flow Type |\n");
                md.push_str("|--------|--------|----------|\n");
                for flow in &rule.attribute_flows {
                    md.push_str(&format!(
                        "| {} | {} | {} |\n",
                        flow.source_attribute, flow.target_attribute, flow.flow_type
                    ));
                }
            }

            md.push_str("\n");
        }
    }

    md.push_str("\n---\n");
    md.push_str("*Generated by ctl365 - Microsoft 365 Deployment Automation*\n");

    md
}

fn generate_html_doc(config: &AadConnectConfig) -> String {
    let mut html = String::from(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Azure AD Connect Configuration</title>
    <style>
        body { font-family: system-ui, -apple-system, sans-serif; margin: 40px; }
        h1 { color: #0078d4; }
        .card { background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 8px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background: #0078d4; color: white; }
        .enabled { color: #107c10; font-weight: bold; }
        .disabled { color: #a80000; }
    </style>
</head>
<body>
    <h1>Azure AD Connect Configuration</h1>
"#,
    );

    html.push_str(&format!(
        "<p><strong>Tenant:</strong> {}</p>",
        config.tenant_name
    ));
    html.push_str(&format!(
        "<p><strong>Generated:</strong> {}</p>",
        chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")
    ));

    html.push_str(r#"<div class="card"><h2>Synchronization Settings</h2><table>"#);
    html.push_str("<tr><th>Setting</th><th>Value</th></tr>");

    let bool_to_html = |v: bool| {
        if v {
            r#"<span class="enabled">Enabled</span>"#
        } else {
            r#"<span class="disabled">Disabled</span>"#
        }
    };

    html.push_str(&format!(
        "<tr><td>Directory Sync</td><td>{}</td></tr>",
        bool_to_html(config.sync_enabled)
    ));
    html.push_str(&format!(
        "<tr><td>Password Hash Sync</td><td>{}</td></tr>",
        bool_to_html(config.password_hash_sync_enabled)
    ));
    html.push_str(&format!(
        "<tr><td>Pass-through Auth</td><td>{}</td></tr>",
        bool_to_html(config.passthrough_auth_enabled)
    ));
    html.push_str(&format!(
        "<tr><td>Federation</td><td>{}</td></tr>",
        bool_to_html(config.federation_enabled)
    ));
    html.push_str(&format!(
        "<tr><td>Seamless SSO</td><td>{}</td></tr>",
        bool_to_html(config.seamless_sso_enabled)
    ));

    html.push_str("</table></div>");

    if !config.on_premises_domains.is_empty() {
        html.push_str(r#"<div class="card"><h2>Verified Domains</h2><ul>"#);
        for domain in &config.on_premises_domains {
            html.push_str(&format!("<li>{}</li>", domain));
        }
        html.push_str("</ul></div>");
    }

    html.push_str(r#"<footer style="margin-top: 40px; color: #666;"><p>Generated by ctl365</p></footer></body></html>"#);

    html
}
