//! ScubaGear Integration - CISA SCuBA Baseline Audits
//!
//! Integrates with CISA's ScubaGear tool for Microsoft 365 security assessments.
//! SCuBA (Secure Cloud Business Applications) provides security configuration baselines.
//!
//! Supported products:
//! - Azure Active Directory (Entra ID)
//! - Microsoft Defender for Office 365
//! - Exchange Online
//! - SharePoint Online
//! - Microsoft Teams
//!
//! Reference: https://github.com/cisagov/ScubaGear

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
pub struct RunAuditArgs {
    /// Products to audit: aad, defender, exchange, sharepoint, teams, or all
    #[arg(short, long, default_value = "all")]
    pub products: String,

    /// Output directory for reports
    #[arg(short, long, default_value = "./scuba-reports")]
    pub output: PathBuf,

    /// Output format: json, html, csv
    #[arg(long, default_value = "html")]
    pub format: String,

    /// Path to existing ScubaGear installation (optional)
    #[arg(long)]
    pub scuba_path: Option<PathBuf>,

    /// Run in offline mode (use previously collected data)
    #[arg(long)]
    pub offline: bool,

    /// Dry run - show what would be audited
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct CheckStatusArgs {
    /// Check ScubaGear installation status
    #[arg(long)]
    pub installation: bool,

    /// Check last audit date
    #[arg(long)]
    pub last_audit: bool,
}

#[derive(Args, Debug)]
pub struct BaselineArgs {
    /// Baseline ID to view/export
    #[arg(short, long)]
    pub baseline: Option<String>,

    /// List all available baselines
    #[arg(long)]
    pub list: bool,

    /// Export baseline to JSON
    #[arg(long)]
    pub export: Option<PathBuf>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScubaAuditResult {
    pub product: String,
    pub baseline_version: String,
    pub audit_date: String,
    pub tenant_id: String,
    pub overall_score: f32,
    pub controls_passed: u32,
    pub controls_failed: u32,
    pub controls_warning: u32,
    pub controls_manual: u32,
    pub findings: Vec<ScubaFinding>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScubaFinding {
    pub control_id: String,
    pub control_title: String,
    pub requirement: String,
    pub status: ScubaStatus,
    pub severity: String,
    pub description: String,
    pub remediation: String,
    pub reference_url: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ScubaStatus {
    Pass,
    Fail,
    Warning,
    Manual,
    NotApplicable,
    Error,
}

/// CISA SCuBA Baseline definitions
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScubaBaseline {
    pub id: String,
    pub name: String,
    pub version: String,
    pub product: String,
    pub controls: Vec<ScubaControl>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScubaControl {
    pub id: String,
    pub title: String,
    pub description: String,
    pub requirement: String,
    pub severity: String,
    pub check_type: String,
    pub remediation: String,
}

/// Run SCuBA baseline audit
pub async fn run_audit(args: RunAuditArgs) -> Result<()> {
    println!("{} SCuBA baseline assessment...", "Running".cyan().bold());

    let products: Vec<&str> = if args.products == "all" {
        vec!["aad", "defender", "exchange", "sharepoint", "teams"]
    } else {
        args.products.split(',').map(|s| s.trim()).collect()
    };

    println!("→ Products: {}", products.join(", ").cyan());
    println!("→ Output: {}", args.output.display().to_string().cyan());
    println!("→ Format: {}", args.format.cyan());

    if args.dry_run {
        println!("\n{} DRY RUN - Would audit:", "ℹ".yellow().bold());
        for product in &products {
            let control_count = get_baseline_control_count(product);
            println!("  {} {} ({} controls)", "•".cyan(), product, control_count);
        }
        return Ok(());
    }

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant".into()))?;

    println!("→ Tenant: {}", active_tenant.name.cyan().bold());

    // Create output directory
    fs::create_dir_all(&args.output)?;

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    let mut all_results: Vec<ScubaAuditResult> = Vec::new();

    for product in products {
        println!("\n{} Auditing {}...", "→".cyan(), product.cyan().bold());

        let result = match product {
            "aad" => audit_aad(&graph, &active_tenant.name).await?,
            "defender" => audit_defender(&graph, &active_tenant.name).await?,
            "exchange" => audit_exchange(&graph, &active_tenant.name).await?,
            "sharepoint" => audit_sharepoint(&graph, &active_tenant.name).await?,
            "teams" => audit_teams(&graph, &active_tenant.name).await?,
            _ => {
                println!("  {} Unknown product: {}", "✗".red(), product);
                continue;
            }
        };

        // Display summary
        display_product_summary(&result);
        all_results.push(result);
    }

    // Generate combined report
    generate_scuba_report(&all_results, &args.output, &args.format)?;

    println!("\n{} SCuBA assessment complete!", "✓".green().bold());
    println!("\nReports saved to: {}", args.output.display());

    // Display overall summary
    let total_passed: u32 = all_results.iter().map(|r| r.controls_passed).sum();
    let total_failed: u32 = all_results.iter().map(|r| r.controls_failed).sum();
    let total_warning: u32 = all_results.iter().map(|r| r.controls_warning).sum();
    let total = total_passed + total_failed + total_warning;

    println!("\n{} Overall Summary:", "→".cyan().bold());
    println!(
        "  Passed: {} ({})",
        total_passed.to_string().green(),
        format!("{:.1}%", (total_passed as f32 / total as f32) * 100.0).green()
    );
    println!("  Failed: {}", total_failed.to_string().red());
    println!("  Warning: {}", total_warning.to_string().yellow());

    Ok(())
}

/// Check ScubaGear status
pub async fn check_status(args: CheckStatusArgs) -> Result<()> {
    println!("{} ScubaGear status...", "Checking".cyan().bold());

    if args.installation {
        // Check if ScubaGear is installed
        println!("\n{} Installation Status:", "→".cyan().bold());

        // Check for PowerShell module
        let ps_result = std::process::Command::new("pwsh")
            .args(["-Command", "Get-Module -ListAvailable ScubaGear"])
            .output();

        match ps_result {
            Ok(output) => {
                if output.stdout.is_empty() {
                    println!("  {} ScubaGear PowerShell module not found", "✗".red());
                    println!("\n  To install:");
                    println!("    Install-Module -Name ScubaGear -Scope CurrentUser");
                } else {
                    println!("  {} ScubaGear PowerShell module installed", "✓".green());
                    let version = String::from_utf8_lossy(&output.stdout);
                    if let Some(line) = version.lines().find(|l| l.contains("ScubaGear")) {
                        println!("    {}", line.trim());
                    }
                }
            }
            Err(_) => {
                println!("  {} PowerShell (pwsh) not available", "✗".yellow());
                println!("  Using built-in SCuBA checks");
            }
        }

        // Check ctl365 built-in SCuBA support
        println!("  {} ctl365 built-in SCuBA checks available", "✓".green());
    }

    if args.last_audit {
        println!("\n{} Last Audit:", "→".cyan().bold());

        // Check for existing audit reports
        let reports_dir = PathBuf::from("./scuba-reports");
        if reports_dir.exists() {
            let mut latest_date = None;
            if let Ok(entries) = fs::read_dir(&reports_dir) {
                for entry in entries.flatten() {
                    if let Ok(metadata) = entry.metadata() {
                        if let Ok(modified) = metadata.modified() {
                            if latest_date.is_none()
                                || latest_date.as_ref().map(|d| modified > *d).unwrap_or(false)
                            {
                                latest_date = Some(modified);
                            }
                        }
                    }
                }
            }
            if let Some(date) = latest_date {
                let datetime: chrono::DateTime<chrono::Utc> = date.into();
                println!("  Last audit: {}", datetime.format("%Y-%m-%d %H:%M UTC"));
            } else {
                println!("  No previous audits found");
            }
        } else {
            println!("  No previous audits found");
        }
    }

    Ok(())
}

/// View or export SCuBA baselines
pub async fn baselines(args: BaselineArgs) -> Result<()> {
    if args.list {
        println!("{} Available SCuBA Baselines:", "Listing".cyan().bold());
        println!();

        let baselines = get_all_baselines();
        for baseline in baselines {
            println!("{} {} (v{})", "•".green(), baseline.name, baseline.version);
            println!("  Product: {}", baseline.product.cyan());
            println!("  Controls: {}", baseline.controls.len());
            println!();
        }

        return Ok(());
    }

    if let Some(baseline_id) = args.baseline {
        let baselines = get_all_baselines();
        if let Some(baseline) = baselines.into_iter().find(|b| b.id == baseline_id) {
            println!("{} {}", "Baseline:".cyan().bold(), baseline.name);
            println!("Version: {}", baseline.version);
            println!("Product: {}", baseline.product);
            println!("\n{} Controls:", "→".cyan());

            for control in &baseline.controls {
                println!("\n  {} {}", control.id.green(), control.title);
                println!(
                    "    Severity: {}",
                    match control.severity.as_str() {
                        "High" | "Critical" => control.severity.red(),
                        "Medium" => control.severity.yellow(),
                        _ => control.severity.normal(),
                    }
                );
                println!("    {}", control.requirement.dimmed());
            }

            if let Some(export_path) = args.export {
                let json = serde_json::to_string_pretty(&baseline)?;
                fs::write(&export_path, json)?;
                println!("\n{} Exported to: {}", "✓".green(), export_path.display());
            }
        } else {
            println!("{} Baseline not found: {}", "✗".red(), baseline_id);
        }
    }

    Ok(())
}

// Product-specific audit functions
async fn audit_aad(graph: &GraphClient, tenant_name: &str) -> Result<ScubaAuditResult> {
    let mut findings = Vec::new();
    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut warning = 0u32;

    // MS.AAD.1.1v1 - Legacy authentication SHALL be blocked
    match graph
        .get_beta::<Value>("identity/conditionalAccess/policies")
        .await
    {
        Ok(response) => {
            let has_legacy_block = response["value"]
                .as_array()
                .map(|policies| {
                    policies.iter().any(|p| {
                        p["conditions"]["clientAppTypes"]
                            .as_array()
                            .map(|types| {
                                types.iter().any(|t| {
                                    t.as_str() == Some("exchangeActiveSync")
                                        || t.as_str() == Some("other")
                                })
                            })
                            .unwrap_or(false)
                            && p["grantControls"]["builtInControls"]
                                .as_array()
                                .map(|controls| {
                                    controls.iter().any(|c| c.as_str() == Some("block"))
                                })
                                .unwrap_or(false)
                    })
                })
                .unwrap_or(false);

            findings.push(ScubaFinding {
                control_id: "MS.AAD.1.1v1".to_string(),
                control_title: "Legacy Authentication".to_string(),
                requirement: "Legacy authentication SHALL be blocked".to_string(),
                status: if has_legacy_block { ScubaStatus::Pass } else { ScubaStatus::Fail },
                severity: "High".to_string(),
                description: "Legacy authentication protocols do not support MFA".to_string(),
                remediation: "Create Conditional Access policy to block legacy auth".to_string(),
                reference_url: Some("https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication".into()),
            });
            if has_legacy_block {
                passed += 1;
            } else {
                failed += 1;
            }
        }
        Err(_) => {
            findings.push(ScubaFinding {
                control_id: "MS.AAD.1.1v1".to_string(),
                control_title: "Legacy Authentication".to_string(),
                requirement: "Legacy authentication SHALL be blocked".to_string(),
                status: ScubaStatus::Error,
                severity: "High".to_string(),
                description: "Could not retrieve CA policies".to_string(),
                remediation: "Verify permissions and retry".to_string(),
                reference_url: None,
            });
            warning += 1;
        }
    }

    // MS.AAD.2.1v1 - Users detected as high risk SHALL be blocked
    findings.push(ScubaFinding {
        control_id: "MS.AAD.2.1v1".to_string(),
        control_title: "High Risk Users".to_string(),
        requirement: "Users detected as high risk SHALL be blocked".to_string(),
        status: ScubaStatus::Manual,
        severity: "High".to_string(),
        description: "Identity Protection should block high-risk users".to_string(),
        remediation: "Configure Identity Protection user risk policy".to_string(),
        reference_url: Some(
            "https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/".into(),
        ),
    });

    // MS.AAD.3.1v1 - MFA SHALL be required
    match graph
        .get_beta::<Value>("identity/conditionalAccess/policies")
        .await
    {
        Ok(response) => {
            let has_mfa = response["value"]
                .as_array()
                .map(|policies| {
                    policies.iter().any(|p| {
                        p["grantControls"]["builtInControls"]
                            .as_array()
                            .map(|controls| controls.iter().any(|c| c.as_str() == Some("mfa")))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);

            findings.push(ScubaFinding {
                control_id: "MS.AAD.3.1v1".to_string(),
                control_title: "MFA Required".to_string(),
                requirement: "MFA SHALL be required for all users".to_string(),
                status: if has_mfa { ScubaStatus::Pass } else { ScubaStatus::Fail },
                severity: "High".to_string(),
                description: "Multi-factor authentication protects against credential theft".to_string(),
                remediation: "Enable MFA via Conditional Access".to_string(),
                reference_url: Some("https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks".into()),
            });
            if has_mfa {
                passed += 1;
            } else {
                failed += 1;
            }
        }
        Err(_) => {
            warning += 1;
        }
    }

    // MS.AAD.3.6v1 - Phishing-resistant MFA SHALL be used for privileged roles
    findings.push(ScubaFinding {
        control_id: "MS.AAD.3.6v1".to_string(),
        control_title: "Phishing-Resistant MFA".to_string(),
        requirement: "Phishing-resistant MFA SHALL be used for privileged roles".to_string(),
        status: ScubaStatus::Manual,
        severity: "High".to_string(),
        description: "FIDO2 or Windows Hello for Business should protect admin accounts".to_string(),
        remediation: "Configure phishing-resistant authentication for admins".to_string(),
        reference_url: Some("https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-passwordless".into()),
    });

    // MS.AAD.7.1v1 - Security defaults SHALL be disabled
    match graph
        .get_beta::<Value>("policies/identitySecurityDefaultsEnforcementPolicy")
        .await
    {
        Ok(response) => {
            let defaults_enabled = response["isEnabled"].as_bool().unwrap_or(false);

            findings.push(ScubaFinding {
                control_id: "MS.AAD.7.1v1".to_string(),
                control_title: "Security Defaults".to_string(),
                requirement: "Security defaults SHALL be disabled (use CA instead)".to_string(),
                status: if !defaults_enabled {
                    ScubaStatus::Pass
                } else {
                    ScubaStatus::Warning
                },
                severity: "Medium".to_string(),
                description: "Security defaults conflict with granular Conditional Access"
                    .to_string(),
                remediation: "Disable security defaults and use Conditional Access policies"
                    .to_string(),
                reference_url: None,
            });
            if !defaults_enabled {
                passed += 1;
            } else {
                warning += 1;
            }
        }
        Err(_) => {
            warning += 1;
        }
    }

    let total = findings.len() as u32;
    let overall_score = if total > 0 {
        (passed as f32 / total as f32) * 100.0
    } else {
        0.0
    };

    Ok(ScubaAuditResult {
        product: "Azure Active Directory".to_string(),
        baseline_version: "1.0".to_string(),
        audit_date: chrono::Utc::now().to_rfc3339(),
        tenant_id: tenant_name.to_string(),
        overall_score,
        controls_passed: passed,
        controls_failed: failed,
        controls_warning: warning,
        controls_manual: findings
            .iter()
            .filter(|f| matches!(f.status, ScubaStatus::Manual))
            .count() as u32,
        findings,
    })
}

async fn audit_defender(_graph: &GraphClient, tenant_name: &str) -> Result<ScubaAuditResult> {
    let mut findings = Vec::new();
    let passed = 0u32;
    let failed = 0u32;
    let warning = 0u32;

    // MS.DEFENDER.1.1v1 - Standard Protection SHALL be enabled
    findings.push(ScubaFinding {
        control_id: "MS.DEFENDER.1.1v1".to_string(),
        control_title: "Standard Protection".to_string(),
        requirement: "Standard Protection SHALL be enabled".to_string(),
        status: ScubaStatus::Manual,
        severity: "High".to_string(),
        description: "Preset security policies provide baseline protection".to_string(),
        remediation: "Enable preset Standard or Strict protection policies".to_string(),
        reference_url: Some("https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/preset-security-policies".into()),
    });

    // MS.DEFENDER.2.1v1 - Safe Links SHALL be enabled
    findings.push(ScubaFinding {
        control_id: "MS.DEFENDER.2.1v1".to_string(),
        control_title: "Safe Links".to_string(),
        requirement: "Safe Links SHALL be enabled".to_string(),
        status: ScubaStatus::Manual,
        severity: "High".to_string(),
        description: "Safe Links scans URLs in emails and documents".to_string(),
        remediation: "Configure Safe Links policy".to_string(),
        reference_url: Some("https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links".into()),
    });

    // MS.DEFENDER.3.1v1 - Safe Attachments SHALL be enabled
    findings.push(ScubaFinding {
        control_id: "MS.DEFENDER.3.1v1".to_string(),
        control_title: "Safe Attachments".to_string(),
        requirement: "Safe Attachments SHALL be enabled".to_string(),
        status: ScubaStatus::Manual,
        severity: "High".to_string(),
        description: "Safe Attachments sandboxes malicious attachments".to_string(),
        remediation: "Configure Safe Attachments policy".to_string(),
        reference_url: Some("https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-attachments".into()),
    });

    // MS.DEFENDER.4.1v1 - Anti-phishing protections SHALL be enabled
    findings.push(ScubaFinding {
        control_id: "MS.DEFENDER.4.1v1".to_string(),
        control_title: "Anti-Phishing".to_string(),
        requirement: "Anti-phishing protections SHALL be enabled".to_string(),
        status: ScubaStatus::Manual,
        severity: "High".to_string(),
        description: "Anti-phishing protects against impersonation attacks".to_string(),
        remediation: "Configure anti-phishing policy with impersonation protection".to_string(),
        reference_url: Some("https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-phishing-protection".into()),
    });

    let total = findings.len() as u32;
    let overall_score = if total > 0 {
        (passed as f32 / total as f32) * 100.0
    } else {
        0.0
    };

    Ok(ScubaAuditResult {
        product: "Microsoft Defender for Office 365".to_string(),
        baseline_version: "1.0".to_string(),
        audit_date: chrono::Utc::now().to_rfc3339(),
        tenant_id: tenant_name.to_string(),
        overall_score,
        controls_passed: passed,
        controls_failed: failed,
        controls_warning: warning,
        controls_manual: findings.len() as u32,
        findings,
    })
}

async fn audit_exchange(_graph: &GraphClient, tenant_name: &str) -> Result<ScubaAuditResult> {
    let mut findings = Vec::new();
    let passed = 0u32;
    let failed = 0u32;
    let warning = 0u32;

    // MS.EXO.1.1v1 - Automatic forwarding SHALL be disabled
    findings.push(ScubaFinding {
        control_id: "MS.EXO.1.1v1".to_string(),
        control_title: "Automatic Forwarding".to_string(),
        requirement: "Automatic forwarding to external domains SHALL be disabled".to_string(),
        status: ScubaStatus::Manual,
        severity: "High".to_string(),
        description: "Auto-forwarding can leak sensitive data to external recipients".to_string(),
        remediation: "Disable auto-forwarding via transport rule or remote domains".to_string(),
        reference_url: Some("https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/remote-domains/manage-remote-domains".into()),
    });

    // MS.EXO.4.1v1 - DKIM SHALL be enabled
    findings.push(ScubaFinding {
        control_id: "MS.EXO.4.1v1".to_string(),
        control_title: "DKIM".to_string(),
        requirement: "DKIM SHALL be enabled for all domains".to_string(),
        status: ScubaStatus::Manual,
        severity: "High".to_string(),
        description: "DKIM prevents email spoofing".to_string(),
        remediation: "Enable DKIM signing for all custom domains".to_string(),
        reference_url: Some("https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dkim-configure".into()),
    });

    // MS.EXO.4.2v1 - DMARC SHALL be enabled
    findings.push(ScubaFinding {
        control_id: "MS.EXO.4.2v1".to_string(),
        control_title: "DMARC".to_string(),
        requirement: "DMARC SHALL be enabled with policy of reject".to_string(),
        status: ScubaStatus::Manual,
        severity: "High".to_string(),
        description: "DMARC protects against domain spoofing".to_string(),
        remediation: "Configure DMARC with p=reject".to_string(),
        reference_url: Some("https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dmarc-configure".into()),
    });

    // MS.EXO.8.1v1 - Audit logging SHALL be enabled
    findings.push(ScubaFinding {
        control_id: "MS.EXO.8.1v1".to_string(),
        control_title: "Audit Logging".to_string(),
        requirement: "Audit logging SHALL be enabled".to_string(),
        status: ScubaStatus::Manual,
        severity: "High".to_string(),
        description: "Audit logs are essential for security monitoring".to_string(),
        remediation: "Enable unified audit log".to_string(),
        reference_url: Some("https://learn.microsoft.com/en-us/microsoft-365/compliance/turn-audit-log-search-on-or-off".into()),
    });

    let total = findings.len() as u32;
    let overall_score = if total > 0 {
        (passed as f32 / total as f32) * 100.0
    } else {
        0.0
    };

    Ok(ScubaAuditResult {
        product: "Exchange Online".to_string(),
        baseline_version: "1.0".to_string(),
        audit_date: chrono::Utc::now().to_rfc3339(),
        tenant_id: tenant_name.to_string(),
        overall_score,
        controls_passed: passed,
        controls_failed: failed,
        controls_warning: warning,
        controls_manual: findings.len() as u32,
        findings,
    })
}

async fn audit_sharepoint(_graph: &GraphClient, tenant_name: &str) -> Result<ScubaAuditResult> {
    let mut findings = Vec::new();

    // MS.SHAREPOINT.1.1v1 - External sharing SHALL be restricted
    findings.push(ScubaFinding {
        control_id: "MS.SHAREPOINT.1.1v1".to_string(),
        control_title: "External Sharing".to_string(),
        requirement: "External sharing SHALL be restricted".to_string(),
        status: ScubaStatus::Manual,
        severity: "High".to_string(),
        description: "Restrict external sharing to prevent data leakage".to_string(),
        remediation: "Configure sharing settings in SharePoint admin center".to_string(),
        reference_url: Some(
            "https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off".into(),
        ),
    });

    // MS.SHAREPOINT.2.1v1 - File and folder links SHALL be restricted
    findings.push(ScubaFinding {
        control_id: "MS.SHAREPOINT.2.1v1".to_string(),
        control_title: "Default Link Type".to_string(),
        requirement: "Default link type SHALL be restricted".to_string(),
        status: ScubaStatus::Manual,
        severity: "Medium".to_string(),
        description: "Default sharing links should not be anonymous".to_string(),
        remediation: "Set default link type to 'Specific people'".to_string(),
        reference_url: None,
    });

    // MS.SHAREPOINT.3.1v1 - Expiration date SHALL be set for guest access
    findings.push(ScubaFinding {
        control_id: "MS.SHAREPOINT.3.1v1".to_string(),
        control_title: "Guest Access Expiration".to_string(),
        requirement: "Guest access SHALL expire".to_string(),
        status: ScubaStatus::Manual,
        severity: "Medium".to_string(),
        description: "Guest access should have expiration dates".to_string(),
        remediation: "Configure guest access expiration in sharing settings".to_string(),
        reference_url: None,
    });

    Ok(ScubaAuditResult {
        product: "SharePoint Online".to_string(),
        baseline_version: "1.0".to_string(),
        audit_date: chrono::Utc::now().to_rfc3339(),
        tenant_id: tenant_name.to_string(),
        overall_score: 0.0,
        controls_passed: 0,
        controls_failed: 0,
        controls_warning: 0,
        controls_manual: findings.len() as u32,
        findings,
    })
}

async fn audit_teams(_graph: &GraphClient, tenant_name: &str) -> Result<ScubaAuditResult> {
    let mut findings = Vec::new();

    // MS.TEAMS.1.1v1 - External access SHALL be restricted
    findings.push(ScubaFinding {
        control_id: "MS.TEAMS.1.1v1".to_string(),
        control_title: "External Access".to_string(),
        requirement: "External access SHALL be restricted".to_string(),
        status: ScubaStatus::Manual,
        severity: "High".to_string(),
        description: "External federation should be controlled".to_string(),
        remediation: "Configure external access in Teams admin center".to_string(),
        reference_url: Some(
            "https://learn.microsoft.com/en-us/microsoftteams/manage-external-access".into(),
        ),
    });

    // MS.TEAMS.2.1v1 - Guest access SHALL be restricted
    findings.push(ScubaFinding {
        control_id: "MS.TEAMS.2.1v1".to_string(),
        control_title: "Guest Access".to_string(),
        requirement: "Guest access SHALL be restricted".to_string(),
        status: ScubaStatus::Manual,
        severity: "Medium".to_string(),
        description: "Guest access should be controlled".to_string(),
        remediation: "Configure guest access settings".to_string(),
        reference_url: Some("https://learn.microsoft.com/en-us/microsoftteams/guest-access".into()),
    });

    // MS.TEAMS.5.1v1 - DLP policies SHALL be enabled
    findings.push(ScubaFinding {
        control_id: "MS.TEAMS.5.1v1".to_string(),
        control_title: "DLP Policies".to_string(),
        requirement: "DLP policies SHALL be enabled for Teams".to_string(),
        status: ScubaStatus::Manual,
        severity: "High".to_string(),
        description: "Data Loss Prevention protects sensitive information".to_string(),
        remediation: "Configure DLP policies for Teams messages".to_string(),
        reference_url: Some(
            "https://learn.microsoft.com/en-us/microsoft-365/compliance/dlp-microsoft-teams".into(),
        ),
    });

    Ok(ScubaAuditResult {
        product: "Microsoft Teams".to_string(),
        baseline_version: "1.0".to_string(),
        audit_date: chrono::Utc::now().to_rfc3339(),
        tenant_id: tenant_name.to_string(),
        overall_score: 0.0,
        controls_passed: 0,
        controls_failed: 0,
        controls_warning: 0,
        controls_manual: findings.len() as u32,
        findings,
    })
}

fn display_product_summary(result: &ScubaAuditResult) {
    println!("  {} {} Assessment:", "•".green(), result.product);
    println!("    Score: {:.1}%", result.overall_score);
    println!(
        "    Passed: {} | Failed: {} | Warning: {} | Manual: {}",
        result.controls_passed.to_string().green(),
        result.controls_failed.to_string().red(),
        result.controls_warning.to_string().yellow(),
        result.controls_manual
    );
}

fn generate_scuba_report(
    results: &[ScubaAuditResult],
    output_dir: &PathBuf,
    format: &str,
) -> Result<()> {
    match format {
        "json" => {
            let json = serde_json::to_string_pretty(&results)?;
            fs::write(output_dir.join("scuba_report.json"), json)?;
        }
        "html" => {
            let html = generate_html_report(results);
            fs::write(output_dir.join("scuba_report.html"), html)?;
        }
        "csv" => {
            let csv = generate_csv_report(results);
            fs::write(output_dir.join("scuba_report.csv"), csv)?;
        }
        _ => {
            let json = serde_json::to_string_pretty(&results)?;
            fs::write(output_dir.join("scuba_report.json"), json)?;
        }
    }

    Ok(())
}

fn generate_html_report(results: &[ScubaAuditResult]) -> String {
    let mut html = String::from(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>SCuBA Baseline Assessment Report</title>
    <style>
        body { font-family: system-ui, -apple-system, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #0078d4; }
        .card { background: white; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .score { font-size: 48px; font-weight: bold; }
        .score.pass { color: #107c10; }
        .score.fail { color: #d83b01; }
        .score.warning { color: #ffaa44; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background: #0078d4; color: white; }
        .status-pass { background: #dff6dd; color: #107c10; }
        .status-fail { background: #fde7e9; color: #a80000; }
        .status-warning { background: #fff4ce; color: #797673; }
        .status-manual { background: #f3f2f1; color: #605e5c; }
        .badge { padding: 4px 12px; border-radius: 4px; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>CISA SCuBA Baseline Assessment</h1>
        <p>Generated: "#,
    );

    html.push_str(&chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string());
    html.push_str(r#"</p>"#);

    // Summary card
    let total_passed: u32 = results.iter().map(|r| r.controls_passed).sum();
    let total_failed: u32 = results.iter().map(|r| r.controls_failed).sum();
    let total_warning: u32 = results.iter().map(|r| r.controls_warning).sum();
    let total_manual: u32 = results.iter().map(|r| r.controls_manual).sum();
    let total = total_passed + total_failed + total_warning;
    let overall = if total > 0 {
        (total_passed as f32 / total as f32) * 100.0
    } else {
        0.0
    };

    let score_class = if overall >= 80.0 {
        "pass"
    } else if overall >= 50.0 {
        "warning"
    } else {
        "fail"
    };

    html.push_str(&format!(
        r#"
        <div class="card">
            <h2>Overall Summary</h2>
            <div class="score {}">{:.0}%</div>
            <p>Passed: {} | Failed: {} | Warning: {} | Manual Review: {}</p>
        </div>
    "#,
        score_class, overall, total_passed, total_failed, total_warning, total_manual
    ));

    // Product details
    for result in results {
        html.push_str(&format!(
            r#"
        <div class="card">
            <h2>{}</h2>
            <p>Baseline Version: {} | Audit Date: {}</p>
            <table>
                <tr>
                    <th>Control ID</th>
                    <th>Title</th>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>Remediation</th>
                </tr>
        "#,
            result.product,
            result.baseline_version,
            result
                .audit_date
                .split('T')
                .next()
                .unwrap_or(&result.audit_date)
        ));

        for finding in &result.findings {
            let status_class = match finding.status {
                ScubaStatus::Pass => "status-pass",
                ScubaStatus::Fail => "status-fail",
                ScubaStatus::Warning => "status-warning",
                _ => "status-manual",
            };
            let status_text = match finding.status {
                ScubaStatus::Pass => "Pass",
                ScubaStatus::Fail => "Fail",
                ScubaStatus::Warning => "Warning",
                ScubaStatus::Manual => "Manual",
                ScubaStatus::NotApplicable => "N/A",
                ScubaStatus::Error => "Error",
            };

            html.push_str(&format!(
                r#"
                <tr>
                    <td>{}</td>
                    <td>{}</td>
                    <td><span class="badge {}">{}</span></td>
                    <td>{}</td>
                    <td>{}</td>
                </tr>
            "#,
                finding.control_id,
                finding.control_title,
                status_class,
                status_text,
                finding.severity,
                finding.remediation
            ));
        }

        html.push_str("</table></div>");
    }

    html.push_str(
        r#"
        <footer style="margin-top: 40px; color: #666; text-align: center;">
            <p>Generated by ctl365 - CISA SCuBA Baseline Assessment</p>
            <p><a href="https://github.com/cisagov/ScubaGear">ScubaGear on GitHub</a></p>
        </footer>
    </div>
</body>
</html>"#,
    );

    html
}

fn generate_csv_report(results: &[ScubaAuditResult]) -> String {
    let mut csv =
        String::from("Product,Control ID,Title,Status,Severity,Requirement,Remediation\n");

    for result in results {
        for finding in &result.findings {
            let status = match finding.status {
                ScubaStatus::Pass => "Pass",
                ScubaStatus::Fail => "Fail",
                ScubaStatus::Warning => "Warning",
                ScubaStatus::Manual => "Manual",
                ScubaStatus::NotApplicable => "N/A",
                ScubaStatus::Error => "Error",
            };
            csv.push_str(&format!(
                "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
                result.product,
                finding.control_id,
                finding.control_title,
                status,
                finding.severity,
                finding.requirement,
                finding.remediation
            ));
        }
    }

    csv
}

fn get_baseline_control_count(product: &str) -> usize {
    match product {
        "aad" => 5,
        "defender" => 4,
        "exchange" => 4,
        "sharepoint" => 3,
        "teams" => 3,
        _ => 0,
    }
}

fn get_all_baselines() -> Vec<ScubaBaseline> {
    vec![
        ScubaBaseline {
            id: "aad".to_string(),
            name: "Azure Active Directory (Entra ID)".to_string(),
            version: "1.0".to_string(),
            product: "AAD".to_string(),
            controls: vec![
                ScubaControl {
                    id: "MS.AAD.1.1v1".to_string(),
                    title: "Legacy Authentication".to_string(),
                    description: "Block legacy authentication protocols".to_string(),
                    requirement: "Legacy authentication SHALL be blocked".to_string(),
                    severity: "High".to_string(),
                    check_type: "Automated".to_string(),
                    remediation: "Create CA policy to block legacy auth".to_string(),
                },
                ScubaControl {
                    id: "MS.AAD.3.1v1".to_string(),
                    title: "MFA Required".to_string(),
                    description: "Require MFA for all users".to_string(),
                    requirement: "MFA SHALL be required".to_string(),
                    severity: "High".to_string(),
                    check_type: "Automated".to_string(),
                    remediation: "Enable MFA via Conditional Access".to_string(),
                },
            ],
        },
        ScubaBaseline {
            id: "defender".to_string(),
            name: "Microsoft Defender for Office 365".to_string(),
            version: "1.0".to_string(),
            product: "Defender".to_string(),
            controls: vec![ScubaControl {
                id: "MS.DEFENDER.1.1v1".to_string(),
                title: "Standard Protection".to_string(),
                description: "Enable preset security policies".to_string(),
                requirement: "Standard protection SHALL be enabled".to_string(),
                severity: "High".to_string(),
                check_type: "Manual".to_string(),
                remediation: "Enable Standard or Strict preset policy".to_string(),
            }],
        },
        ScubaBaseline {
            id: "exchange".to_string(),
            name: "Exchange Online".to_string(),
            version: "1.0".to_string(),
            product: "Exchange".to_string(),
            controls: vec![ScubaControl {
                id: "MS.EXO.1.1v1".to_string(),
                title: "Auto-Forwarding".to_string(),
                description: "Disable automatic mail forwarding".to_string(),
                requirement: "Auto-forwarding SHALL be disabled".to_string(),
                severity: "High".to_string(),
                check_type: "Manual".to_string(),
                remediation: "Create transport rule to block forwarding".to_string(),
            }],
        },
        ScubaBaseline {
            id: "sharepoint".to_string(),
            name: "SharePoint Online".to_string(),
            version: "1.0".to_string(),
            product: "SharePoint".to_string(),
            controls: vec![ScubaControl {
                id: "MS.SHAREPOINT.1.1v1".to_string(),
                title: "External Sharing".to_string(),
                description: "Restrict external sharing".to_string(),
                requirement: "External sharing SHALL be restricted".to_string(),
                severity: "High".to_string(),
                check_type: "Manual".to_string(),
                remediation: "Configure sharing in SharePoint admin".to_string(),
            }],
        },
        ScubaBaseline {
            id: "teams".to_string(),
            name: "Microsoft Teams".to_string(),
            version: "1.0".to_string(),
            product: "Teams".to_string(),
            controls: vec![ScubaControl {
                id: "MS.TEAMS.1.1v1".to_string(),
                title: "External Access".to_string(),
                description: "Restrict external federation".to_string(),
                requirement: "External access SHALL be restricted".to_string(),
                severity: "High".to_string(),
                check_type: "Manual".to_string(),
                remediation: "Configure external access in Teams admin".to_string(),
            }],
        },
    ]
}
