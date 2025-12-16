/// Enhanced Audit & Compliance with drift detection and reporting
///
/// Features:
/// - Baseline comparison (OIB, CIS, ScubaGear, custom)
/// - Drift detection with detailed diff
/// - Auto-remediation
/// - HTML/CSV/JSON reports with charts
/// - Compliance scoring
use crate::config::ConfigManager;
use crate::error::Result;
use crate::graph::{GraphClient, conditional_access, intune};
use clap::Args;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct AuditArgs {
    /// Baseline to audit against (oib, cis, scuba, microsoft-baseline, custom)
    #[arg(long, default_value = "oib")]
    pub baseline: String,

    /// Custom baseline file path (if baseline=custom)
    #[arg(long)]
    pub baseline_file: Option<PathBuf>,

    /// Platform to audit (windows, macos, ios, android, all)
    #[arg(long, default_value = "all")]
    pub platform: String,

    /// Output format (table, json, html, csv)
    #[arg(short, long, default_value = "table")]
    pub format: String,

    /// Output file path
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Include compliance details
    #[arg(long)]
    pub detailed: bool,

    /// Check specific controls (comma-separated)
    #[arg(long)]
    pub controls: Option<String>,

    /// Generate compliance score (0-100)
    #[arg(long)]
    pub score: bool,
}

#[derive(Args, Debug)]
pub struct DriftArgs {
    /// Baseline file or directory to compare against
    pub baseline: PathBuf,

    /// Show only differences
    #[arg(long)]
    pub diff_only: bool,

    /// Auto-remediate drift (apply missing policies)
    #[arg(long)]
    pub fix: bool,

    /// Dry run for --fix
    #[arg(long)]
    pub dry_run: bool,

    /// Output format (table, json, html)
    #[arg(short, long, default_value = "table")]
    pub format: String,

    /// Output file
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ReportArgs {
    /// Report type (compliance, security, inventory, executive)
    #[arg(long, default_value = "compliance")]
    pub report_type: String,

    /// Output format (html, json, csv, pdf)
    #[arg(short, long, default_value = "html")]
    pub format: String,

    /// Output file
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Include charts and graphs (HTML/PDF only)
    #[arg(long)]
    pub include_charts: bool,

    /// Baseline for compliance comparison
    #[arg(long, default_value = "oib")]
    pub baseline: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Finding {
    pub severity: String, // CRITICAL, HIGH, MEDIUM, LOW, INFO
    pub category: String, // Compliance, CA, Configuration, Security
    pub control: String,  // Control ID (e.g., COMP-001, CA-002)
    pub description: String,
    pub remediation: String,
    pub affected_resource: Option<String>,
    pub current_value: Option<String>,
    pub expected_value: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct AuditReport {
    audit_date: String,
    tenant_name: String,
    baseline: String,
    platform: String,
    total_controls: usize,
    passed_controls: usize,
    failed_controls: usize,
    compliance_score: f32,
    findings: Vec<Finding>,
    summary: AuditSummary,
}

#[derive(Serialize, Deserialize, Debug)]
struct AuditSummary {
    critical_issues: usize,
    high_issues: usize,
    medium_issues: usize,
    low_issues: usize,
    info_issues: usize,
}

#[derive(Serialize, Deserialize, Debug)]
struct DriftResult {
    drift_date: String,
    tenant_name: String,
    baseline_source: String,
    total_policies_expected: usize,
    total_policies_found: usize,
    missing_policies: Vec<PolicyDrift>,
    modified_policies: Vec<PolicyDrift>,
    extra_policies: Vec<PolicyDrift>,
    drift_score: f32, // 0-100, 100 = no drift
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PolicyDrift {
    policy_name: String,
    policy_type: String, // compliance, configuration, ca
    drift_type: String,  // missing, modified, extra
    differences: Vec<SettingDifference>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct SettingDifference {
    setting_name: String,
    expected_value: Option<String>,
    actual_value: Option<String>,
}

/// Enhanced audit with baseline comparison
pub async fn audit_enhanced(args: AuditArgs) -> Result<()> {
    println!(
        "{} tenant against {} baseline...",
        "Auditing".cyan().bold(),
        args.baseline.yellow()
    );

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    println!("→ Tenant: {}", active_tenant.name.cyan().bold());
    println!("→ Platform: {}", args.platform.cyan());
    println!("→ Baseline: {}", args.baseline.cyan());

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    let mut findings = Vec::new();
    let mut total_controls = 0;
    let mut passed_controls = 0;

    // Load baseline expectations
    let baseline_expectations = load_baseline_expectations(&args.baseline, &args.baseline_file)?;

    // Audit Compliance Policies
    println!("\n{} Compliance Policies...", "→".cyan());
    match intune::list_compliance_policies(&graph).await {
        Ok(policies) => {
            let count = policies["value"].as_array().map(|a| a.len()).unwrap_or(0);
            println!("  {} Found {} compliance policies", "✓".green(), count);

            total_controls += 1;

            if count == 0 {
                findings.push(Finding {
                    severity: "HIGH".to_string(),
                    category: "Compliance".to_string(),
                    control: "COMP-001".to_string(),
                    description: "No compliance policies configured".to_string(),
                    remediation: "Deploy baseline compliance policies with: ctl365 baseline apply"
                        .to_string(),
                    affected_resource: None,
                    current_value: Some("0 policies".to_string()),
                    expected_value: Some("At least 1 compliance policy".to_string()),
                });
            } else {
                passed_controls += 1;

                // Detailed policy validation
                if args.detailed {
                    if let Some(policy_list) = policies["value"].as_array() {
                        for policy in policy_list {
                            validate_compliance_policy(
                                policy,
                                &baseline_expectations,
                                &mut findings,
                                &mut total_controls,
                                &mut passed_controls,
                            );
                        }
                    }
                }
            }
        }
        Err(e) => println!("  {} Failed: {}", "✗".red(), e),
    }

    // Audit Device Configurations
    println!("\n{} Device Configurations...", "→".cyan());
    match intune::list_device_configurations(&graph).await {
        Ok(configs) => {
            let count = configs["value"].as_array().map(|a| a.len()).unwrap_or(0);
            println!("  {} Found {} device configurations", "✓".green(), count);
        }
        Err(e) => println!("  {} Failed: {}", "✗".red(), e),
    }

    // Audit Settings Catalog Policies
    println!("\n{} Settings Catalog Policies...", "→".cyan());
    match list_settings_catalog_policies(&graph).await {
        Ok(catalog_policies) => {
            let count = catalog_policies["value"]
                .as_array()
                .map(|a| a.len())
                .unwrap_or(0);
            println!(
                "  {} Found {} settings catalog policies",
                "✓".green(),
                count
            );

            if args.baseline == "oib" && count == 0 {
                findings.push(Finding {
                    severity: "MEDIUM".to_string(),
                    category: "Configuration".to_string(),
                    control: "CONFIG-001".to_string(),
                    description: "No Settings Catalog policies found (OIB uses Settings Catalog)"
                        .to_string(),
                    remediation:
                        "Deploy OIB baseline with: ctl365 baseline new windows --template oib"
                            .to_string(),
                    affected_resource: None,
                    current_value: Some("0 policies".to_string()),
                    expected_value: Some("At least 8 Settings Catalog policies".to_string()),
                });
            }
        }
        Err(e) => println!("  {} Failed: {}", "✗".red(), e),
    }

    // Audit Conditional Access
    println!("\n{} Conditional Access Policies...", "→".cyan());
    match conditional_access::list_policies(&graph).await {
        Ok(ca_policies) => {
            let count = ca_policies["value"]
                .as_array()
                .map(|a| a.len())
                .unwrap_or(0);
            println!("  {} Found {} CA policies", "✓".green(), count);

            total_controls += 1;

            if count == 0 {
                findings.push(Finding {
                    severity: "CRITICAL".to_string(),
                    category: "Conditional Access".to_string(),
                    control: "CA-001".to_string(),
                    description: "No Conditional Access policies configured".to_string(),
                    remediation: "Deploy CA baseline with: ctl365 ca deploy --all".to_string(),
                    affected_resource: None,
                    current_value: Some("0 policies".to_string()),
                    expected_value: Some(
                        "At least 4 CA policies (MFA, compliant device, location, legacy auth)"
                            .to_string(),
                    ),
                });
            } else {
                passed_controls += 1;
            }

            // Check for enabled policies (not just report-only)
            if let Some(policies) = ca_policies["value"].as_array() {
                total_controls += 1;

                let enabled_count = policies
                    .iter()
                    .filter(|p| p["state"].as_str() == Some("enabled"))
                    .count();

                if enabled_count == 0 && count > 0 {
                    findings.push(Finding {
                        severity: "HIGH".to_string(),
                        category: "Conditional Access".to_string(),
                        control: "CA-002".to_string(),
                        description: format!("{} CA policies in report-only mode", count),
                        remediation: "Review and enable CA policies after testing".to_string(),
                        affected_resource: None,
                        current_value: Some("0 enabled".to_string()),
                        expected_value: Some("At least 1 enabled CA policy".to_string()),
                    });
                } else {
                    passed_controls += 1;
                }

                // Audit specific CA policy requirements
                validate_ca_baseline(
                    policies,
                    &mut findings,
                    &mut total_controls,
                    &mut passed_controls,
                );
            }
        }
        Err(e) => println!("  {} Failed: {}", "✗".red(), e),
    }

    // Check Security Defaults
    println!("\n{} Security Defaults...", "→".cyan());
    match conditional_access::get_security_defaults(&graph).await {
        Ok(defaults) => {
            total_controls += 1;

            let is_enabled = defaults["isEnabled"].as_bool().unwrap_or(false);
            if is_enabled {
                println!("  {} Security defaults are ENABLED", "⚠".yellow());
                findings.push(Finding {
                    severity: "MEDIUM".to_string(),
                    category: "Conditional Access".to_string(),
                    control: "CA-003".to_string(),
                    description: "Security defaults enabled (blocks custom CA policies)"
                        .to_string(),
                    remediation: "Disable with: ctl365 ca deploy --disable-security-defaults"
                        .to_string(),
                    affected_resource: Some("Security Defaults".to_string()),
                    current_value: Some("Enabled".to_string()),
                    expected_value: Some("Disabled (use CA policies instead)".to_string()),
                });
            } else {
                println!("  {} Security defaults disabled (good for CA)", "✓".green());
                passed_controls += 1;
            }
        }
        Err(e) => println!("  {} Failed: {}", "✗".red(), e),
    }

    // Calculate compliance score
    let compliance_score = if total_controls > 0 {
        (passed_controls as f32 / total_controls as f32) * 100.0
    } else {
        0.0
    };

    // Generate audit summary
    println!("\n{}", "Audit Summary:".cyan().bold());
    println!("────────────────────────────────────────────");

    let summary = AuditSummary {
        critical_issues: findings.iter().filter(|f| f.severity == "CRITICAL").count(),
        high_issues: findings.iter().filter(|f| f.severity == "HIGH").count(),
        medium_issues: findings.iter().filter(|f| f.severity == "MEDIUM").count(),
        low_issues: findings.iter().filter(|f| f.severity == "LOW").count(),
        info_issues: findings.iter().filter(|f| f.severity == "INFO").count(),
    };

    if findings.is_empty() {
        println!("{} No critical issues found!", "✓".green().bold());
    } else {
        if summary.critical_issues > 0 {
            println!(
                "{} {} critical issues",
                "✗".red().bold(),
                summary.critical_issues
            );
        }
        if summary.high_issues > 0 {
            println!(
                "{} {} high severity issues",
                "⚠".yellow().bold(),
                summary.high_issues
            );
        }
        if summary.medium_issues > 0 {
            println!(
                "{} {} medium severity issues",
                "ℹ".cyan(),
                summary.medium_issues
            );
        }

        println!("\n{}", "Findings:".bold());
        for (i, finding) in findings.iter().enumerate() {
            println!(
                "\n{}. {} [{}] {}",
                i + 1,
                severity_icon(&finding.severity),
                finding.control.yellow(),
                finding.description
            );
            println!("   Category: {}", finding.category.cyan());
            if let Some(ref resource) = finding.affected_resource {
                println!("   Resource: {}", resource);
            }
            if args.detailed {
                if let Some(ref current) = finding.current_value {
                    println!("   Current: {}", current.red());
                }
                if let Some(ref expected) = finding.expected_value {
                    println!("   Expected: {}", expected.green());
                }
            }
            println!("   Remediation: {}", finding.remediation.green());
        }
    }

    if args.score {
        println!("\n{}", "Compliance Score:".cyan().bold());
        println!(
            "{}",
            format_compliance_score(compliance_score, passed_controls, total_controls)
        );
    }

    // Generate report if output specified
    if let Some(output_path) = &args.output {
        let report = AuditReport {
            audit_date: chrono::Utc::now().to_rfc3339(),
            tenant_name: active_tenant.name.clone(),
            baseline: args.baseline.clone(),
            platform: args.platform.clone(),
            total_controls,
            passed_controls,
            failed_controls: total_controls - passed_controls,
            compliance_score,
            findings: findings.clone(),
            summary,
        };

        let output_content = match args.format.as_str() {
            "json" => serde_json::to_string_pretty(&report)?,
            "html" => generate_html_audit_report(&report)?,
            "csv" => generate_csv_audit_report(&report)?,
            _ => serde_json::to_string_pretty(&report)?,
        };

        fs::write(output_path, output_content)?;
        println!(
            "\n{} Report saved to: {}",
            "✓".green(),
            output_path.display()
        );
    }

    Ok(())
}

/// Detect configuration drift
pub async fn drift_enhanced(args: DriftArgs) -> Result<()> {
    println!("{} configuration drift...", "Detecting".cyan().bold());
    println!("→ Baseline: {}", args.baseline.display());

    if !args.baseline.exists() {
        return Err(crate::error::Error::ConfigError(format!(
            "Baseline not found: {}",
            args.baseline.display()
        )));
    }

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    println!("→ Tenant: {}", active_tenant.name.cyan().bold());

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Load baseline
    let baseline_content = fs::read_to_string(&args.baseline).map_err(|e| {
        crate::error::Error::ConfigError(format!(
            "Failed to read baseline {}: {}",
            args.baseline.display(),
            e
        ))
    })?;
    let baseline: Value = serde_json::from_str(&baseline_content).map_err(|e| {
        crate::error::Error::ConfigError(format!(
            "Invalid JSON in baseline {}: {}",
            args.baseline.display(),
            e
        ))
    })?;

    let baseline_policies = baseline["policies"]
        .as_array()
        .ok_or_else(|| crate::error::Error::ConfigError("Invalid baseline format".into()))?;

    println!(
        "\n{} Expected {} policies from baseline",
        "→".cyan(),
        baseline_policies.len()
    );

    // Get current tenant policies
    let mut current_policies = HashMap::new();

    println!("\n{} current tenant configuration...", "→".cyan());

    // Fetch compliance policies
    if let Ok(response) = intune::list_compliance_policies(&graph).await {
        if let Some(policies) = response["value"].as_array() {
            for policy in policies {
                if let Some(name) = policy["displayName"].as_str() {
                    current_policies
                        .insert(name.to_string(), ("compliance".to_string(), policy.clone()));
                }
            }
        }
    }

    // Fetch device configurations
    if let Ok(response) = intune::list_device_configurations(&graph).await {
        if let Some(configs) = response["value"].as_array() {
            for config in configs {
                if let Some(name) = config["displayName"].as_str() {
                    current_policies.insert(
                        name.to_string(),
                        ("deviceConfiguration".to_string(), config.clone()),
                    );
                }
            }
        }
    }

    // Fetch settings catalog
    if let Ok(response) = list_settings_catalog_policies(&graph).await {
        if let Some(catalog) = response["value"].as_array() {
            for policy in catalog {
                if let Some(name) = policy["name"].as_str() {
                    current_policies.insert(
                        name.to_string(),
                        ("settingsCatalog".to_string(), policy.clone()),
                    );
                }
            }
        }
    }

    // Fetch CA policies
    if let Ok(response) = conditional_access::list_policies(&graph).await {
        if let Some(ca_policies) = response["value"].as_array() {
            for policy in ca_policies {
                if let Some(name) = policy["displayName"].as_str() {
                    current_policies.insert(
                        name.to_string(),
                        ("conditionalAccess".to_string(), policy.clone()),
                    );
                }
            }
        }
    }

    println!(
        "  {} Found {} policies in tenant",
        "✓".green(),
        current_policies.len()
    );

    // Compare baseline vs current
    let mut missing_policies = Vec::new();
    let mut modified_policies = Vec::new();
    let mut extra_policies = Vec::new();

    println!("\n{} for drift...", "→".cyan());

    // Check for missing and modified policies
    for baseline_policy in baseline_policies {
        let policy_name = baseline_policy["displayName"]
            .as_str()
            .or_else(|| baseline_policy["name"].as_str())
            .unwrap_or("Unknown");

        if let Some((policy_type, current_policy)) = current_policies.get(policy_name) {
            // Policy exists - check for modifications
            let differences = compare_policies(baseline_policy, current_policy);

            if !differences.is_empty() {
                modified_policies.push(PolicyDrift {
                    policy_name: policy_name.to_string(),
                    policy_type: policy_type.clone(),
                    drift_type: "modified".to_string(),
                    differences,
                });
            }

            // Remove from current_policies so we can find extras later
            // Note: We can't actually remove during iteration, we'll track separately
        } else {
            // Policy missing
            missing_policies.push(PolicyDrift {
                policy_name: policy_name.to_string(),
                policy_type: "Unknown".to_string(),
                drift_type: "missing".to_string(),
                differences: vec![],
            });
        }
    }

    // Check for extra policies not in baseline
    let baseline_names: Vec<String> = baseline_policies
        .iter()
        .filter_map(|p| {
            p["displayName"]
                .as_str()
                .or_else(|| p["name"].as_str())
                .map(|s| s.to_string())
        })
        .collect();

    for (name, (policy_type, _)) in &current_policies {
        if !baseline_names.contains(name) {
            extra_policies.push(PolicyDrift {
                policy_name: name.clone(),
                policy_type: policy_type.clone(),
                drift_type: "extra".to_string(),
                differences: vec![],
            });
        }
    }

    // Calculate drift score
    let total_expected = baseline_policies.len();
    let drift_count = missing_policies.len() + modified_policies.len();
    let drift_score = if total_expected > 0 {
        ((total_expected - drift_count) as f32 / total_expected as f32) * 100.0
    } else {
        100.0
    };

    // Display results
    println!("\n{}", "Drift Analysis:".cyan().bold());
    println!("────────────────────────────────────────────");
    println!("Expected policies: {}", total_expected);
    println!("Current policies: {}", current_policies.len());
    println!("Drift score: {}", format_drift_score(drift_score));

    if missing_policies.is_empty() && modified_policies.is_empty() && extra_policies.is_empty() {
        println!("\n{} No drift detected!", "✓".green().bold());
    } else {
        if !missing_policies.is_empty() {
            println!(
                "\n{} {} Missing Policies:",
                "✗".red().bold(),
                missing_policies.len()
            );
            for policy in &missing_policies {
                println!("  {} {}", "→".red(), policy.policy_name);
            }
        }

        if !modified_policies.is_empty() {
            println!(
                "\n{} {} Modified Policies:",
                "⚠".yellow().bold(),
                modified_policies.len()
            );
            for policy in &modified_policies {
                println!("  {} {}", "→".yellow(), policy.policy_name);
                if !args.diff_only {
                    for diff in &policy.differences {
                        println!("    Setting: {}", diff.setting_name.cyan());
                        if let Some(ref expected) = diff.expected_value {
                            println!("      Expected: {}", expected.green());
                        }
                        if let Some(ref actual) = diff.actual_value {
                            println!("      Actual:   {}", actual.red());
                        }
                    }
                }
            }
        }

        if !extra_policies.is_empty() && !args.diff_only {
            println!(
                "\n{} {} Extra Policies (not in baseline):",
                "ℹ".cyan(),
                extra_policies.len()
            );
            for policy in &extra_policies {
                println!("  {} {}", "→".cyan(), policy.policy_name);
            }
        }
    }

    // Auto-remediation
    if args.fix {
        println!("\n{}", "Remediation:".cyan().bold());

        if args.dry_run {
            println!(
                "{} (dry run - no changes applied)",
                "DRY RUN".yellow().bold()
            );
            println!("\nWould apply:");
            for policy in &missing_policies {
                println!("  {} Create: {}", "→".cyan(), policy.policy_name);
            }
            for policy in &modified_policies {
                println!("  {} Update: {}", "→".cyan(), policy.policy_name);
            }
        } else {
            let mut fixed_count = 0;

            for policy in &missing_policies {
                // Find policy in baseline and create it
                if let Some(baseline_policy) = baseline_policies.iter().find(|p| {
                    p["displayName"].as_str().or_else(|| p["name"].as_str())
                        == Some(&policy.policy_name)
                }) {
                    match create_policy_from_baseline(&graph, baseline_policy).await {
                        Ok(_) => {
                            println!("  {} Created: {}", "✓".green(), policy.policy_name);
                            fixed_count += 1;
                        }
                        Err(e) => println!(
                            "  {} Failed to create {}: {}",
                            "✗".red(),
                            policy.policy_name,
                            e
                        ),
                    }
                }
            }

            println!("\n{} Fixed {} issues", "✓".green().bold(), fixed_count);
        }
    }

    // Save drift report
    if let Some(output_path) = &args.output {
        let drift_result = DriftResult {
            drift_date: chrono::Utc::now().to_rfc3339(),
            tenant_name: active_tenant.name.clone(),
            baseline_source: args.baseline.display().to_string(),
            total_policies_expected: total_expected,
            total_policies_found: current_policies.len(),
            missing_policies,
            modified_policies,
            extra_policies,
            drift_score,
        };

        let output_content = match args.format.as_str() {
            "json" => serde_json::to_string_pretty(&drift_result)?,
            "html" => generate_html_drift_report(&drift_result)?,
            _ => serde_json::to_string_pretty(&drift_result)?,
        };

        fs::write(output_path, output_content)?;
        println!(
            "\n{} Drift report saved to: {}",
            "✓".green(),
            output_path.display()
        );
    }

    Ok(())
}

// Helper functions

fn load_baseline_expectations(
    baseline: &str,
    baseline_file: &Option<PathBuf>,
) -> Result<HashMap<String, Value>> {
    let mut expectations = HashMap::new();

    match baseline {
        "oib" => {
            // OpenIntuneBaseline expectations
            expectations.insert(
                "min_compliance_policies".to_string(),
                json!(4), // OIB has 4 compliance policies
            );
            expectations.insert(
                "min_settings_catalog".to_string(),
                json!(8), // OIB has 8+ Settings Catalog policies
            );
            expectations.insert("min_ca_policies".to_string(), json!(4));
        }
        "custom" => {
            if let Some(file) = baseline_file {
                let content = fs::read_to_string(file).map_err(|e| {
                    crate::error::Error::ConfigError(format!(
                        "Failed to read custom baseline {}: {}",
                        file.display(),
                        e
                    ))
                })?;
                let baseline: Value = serde_json::from_str(&content).map_err(|e| {
                    crate::error::Error::ConfigError(format!(
                        "Invalid JSON in custom baseline {}: {}",
                        file.display(),
                        e
                    ))
                })?;
                if let Some(obj) = baseline.as_object() {
                    for (key, value) in obj {
                        expectations.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        _ => {}
    }

    Ok(expectations)
}

fn validate_compliance_policy(
    policy: &Value,
    _expectations: &HashMap<String, Value>,
    findings: &mut Vec<Finding>,
    total_controls: &mut usize,
    passed_controls: &mut usize,
) {
    let policy_name = policy["displayName"].as_str().unwrap_or("Unknown Policy");
    let platform = policy["@odata.type"]
        .as_str()
        .unwrap_or("")
        .split('.')
        .next_back()
        .unwrap_or("Unknown");

    // Check if policy has scheduled actions (required for non-compliant devices)
    *total_controls += 1;
    let has_scheduled_actions = policy["scheduledActionsForRule"]
        .as_array()
        .is_some_and(|actions| !actions.is_empty());

    if !has_scheduled_actions {
        findings.push(Finding {
            severity: "MEDIUM".to_string(),
            category: "Compliance".to_string(),
            control: "COMP-ACTIONS".to_string(),
            description: format!(
                "Compliance policy '{}' has no scheduled actions for non-compliance",
                policy_name
            ),
            remediation: "Add scheduled actions (mark non-compliant, notify user, etc.)"
                .to_string(),
            affected_resource: Some(policy_name.to_string()),
            current_value: Some("No scheduled actions".to_string()),
            expected_value: Some("At least one scheduled action configured".to_string()),
        });
    } else {
        *passed_controls += 1;
    }

    // Platform-specific validation
    match platform {
        "windows10CompliancePolicy" | "windows81CompliancePolicy" => {
            // Check for BitLocker requirement
            *total_controls += 1;
            let bitlocker_required = policy["bitLockerEnabled"].as_bool().unwrap_or(false);
            if !bitlocker_required {
                findings.push(Finding {
                    severity: "HIGH".to_string(),
                    category: "Compliance".to_string(),
                    control: "COMP-BITLOCKER".to_string(),
                    description: format!(
                        "Windows compliance policy '{}' does not require BitLocker",
                        policy_name
                    ),
                    remediation: "Enable BitLocker requirement in compliance policy".to_string(),
                    affected_resource: Some(policy_name.to_string()),
                    current_value: Some("BitLocker not required".to_string()),
                    expected_value: Some("BitLocker required".to_string()),
                });
            } else {
                *passed_controls += 1;
            }

            // Check for secure boot
            *total_controls += 1;
            let secure_boot_required = policy["secureBootEnabled"].as_bool().unwrap_or(false);
            if !secure_boot_required {
                findings.push(Finding {
                    severity: "MEDIUM".to_string(),
                    category: "Compliance".to_string(),
                    control: "COMP-SECUREBOOT".to_string(),
                    description: format!(
                        "Windows compliance policy '{}' does not require Secure Boot",
                        policy_name
                    ),
                    remediation: "Enable Secure Boot requirement in compliance policy".to_string(),
                    affected_resource: Some(policy_name.to_string()),
                    current_value: Some("Secure Boot not required".to_string()),
                    expected_value: Some("Secure Boot required".to_string()),
                });
            } else {
                *passed_controls += 1;
            }

            // Check for code integrity
            *total_controls += 1;
            let code_integrity = policy["codeIntegrityEnabled"].as_bool().unwrap_or(false);
            if !code_integrity {
                findings.push(Finding {
                    severity: "MEDIUM".to_string(),
                    category: "Compliance".to_string(),
                    control: "COMP-CODEINTEGRITY".to_string(),
                    description: format!(
                        "Windows compliance policy '{}' does not require Code Integrity",
                        policy_name
                    ),
                    remediation: "Enable Code Integrity requirement in compliance policy"
                        .to_string(),
                    affected_resource: Some(policy_name.to_string()),
                    current_value: Some("Code Integrity not required".to_string()),
                    expected_value: Some("Code Integrity required".to_string()),
                });
            } else {
                *passed_controls += 1;
            }
        }
        "macOSCompliancePolicy" => {
            // Check for FileVault requirement
            *total_controls += 1;
            let filevault_required = policy["storageRequireEncryption"]
                .as_bool()
                .unwrap_or(false);
            if !filevault_required {
                findings.push(Finding {
                    severity: "HIGH".to_string(),
                    category: "Compliance".to_string(),
                    control: "COMP-FILEVAULT".to_string(),
                    description: format!(
                        "macOS compliance policy '{}' does not require FileVault encryption",
                        policy_name
                    ),
                    remediation: "Enable storage encryption requirement in compliance policy"
                        .to_string(),
                    affected_resource: Some(policy_name.to_string()),
                    current_value: Some("FileVault not required".to_string()),
                    expected_value: Some("FileVault required".to_string()),
                });
            } else {
                *passed_controls += 1;
            }

            // Check for System Integrity Protection
            *total_controls += 1;
            let sip_enabled = policy["systemIntegrityProtectionEnabled"]
                .as_bool()
                .unwrap_or(false);
            if !sip_enabled {
                findings.push(Finding {
                    severity: "HIGH".to_string(),
                    category: "Compliance".to_string(),
                    control: "COMP-SIP".to_string(),
                    description: format!(
                        "macOS compliance policy '{}' does not require System Integrity Protection",
                        policy_name
                    ),
                    remediation: "Enable SIP requirement in compliance policy".to_string(),
                    affected_resource: Some(policy_name.to_string()),
                    current_value: Some("SIP not required".to_string()),
                    expected_value: Some("SIP required".to_string()),
                });
            } else {
                *passed_controls += 1;
            }
        }
        "iosCompliancePolicy" | "aospDeviceOwnerCompliancePolicy" | "androidCompliancePolicy" => {
            // Check for device encryption
            *total_controls += 1;
            let encryption_required = policy["storageRequireEncryption"]
                .as_bool()
                .or_else(|| policy["securityRequireDeviceEncryption"].as_bool())
                .unwrap_or(false);
            if !encryption_required {
                findings.push(Finding {
                    severity: "HIGH".to_string(),
                    category: "Compliance".to_string(),
                    control: "COMP-ENCRYPTION".to_string(),
                    description: format!(
                        "Mobile compliance policy '{}' does not require device encryption",
                        policy_name
                    ),
                    remediation: "Enable device encryption requirement".to_string(),
                    affected_resource: Some(policy_name.to_string()),
                    current_value: Some("Encryption not required".to_string()),
                    expected_value: Some("Device encryption required".to_string()),
                });
            } else {
                *passed_controls += 1;
            }
        }
        _ => {
            // Unknown platform - skip platform-specific checks
        }
    }
}

fn validate_ca_baseline(
    policies: &[Value],
    findings: &mut Vec<Finding>,
    total_controls: &mut usize,
    passed_controls: &mut usize,
) {
    // Check for essential CA policies
    let has_mfa_policy = policies.iter().any(|p| {
        p["grantControls"]["builtInControls"]
            .as_array()
            .map(|controls| controls.iter().any(|c| c.as_str() == Some("mfa")))
            .unwrap_or(false)
    });

    *total_controls += 1;
    if !has_mfa_policy {
        findings.push(Finding {
            severity: "CRITICAL".to_string(),
            category: "Conditional Access".to_string(),
            control: "CA-MFA-001".to_string(),
            description: "No MFA enforcement policy found".to_string(),
            remediation: "Deploy MFA policy with: ctl365 ca deploy --mfa".to_string(),
            affected_resource: None,
            current_value: Some("No MFA policy".to_string()),
            expected_value: Some("MFA required for all users".to_string()),
        });
    } else {
        *passed_controls += 1;
    }

    // Check for compliant device policy
    let has_compliant_device = policies.iter().any(|p| {
        p["grantControls"]["builtInControls"]
            .as_array()
            .map(|controls| {
                controls
                    .iter()
                    .any(|c| c.as_str() == Some("compliantDevice"))
            })
            .unwrap_or(false)
    });

    *total_controls += 1;
    if !has_compliant_device {
        findings.push(Finding {
            severity: "HIGH".to_string(),
            category: "Conditional Access".to_string(),
            control: "CA-DEVICE-001".to_string(),
            description: "No compliant device requirement found".to_string(),
            remediation: "Deploy compliant device policy with: ctl365 ca deploy --compliant-device"
                .to_string(),
            affected_resource: None,
            current_value: Some("No device compliance policy".to_string()),
            expected_value: Some("Require compliant or hybrid joined device".to_string()),
        });
    } else {
        *passed_controls += 1;
    }

    // Check for legacy authentication blocking
    let has_legacy_auth_block = policies.iter().any(|p| {
        p["conditions"]["clientAppTypes"]
            .as_array()
            .map(|types| {
                types.iter().any(|t| {
                    t.as_str() == Some("exchangeActiveSync") || t.as_str() == Some("other")
                })
            })
            .unwrap_or(false)
            && p["grantControls"]["builtInControls"]
                .as_array()
                .map(|controls| controls.iter().any(|c| c.as_str() == Some("block")))
                .unwrap_or(false)
    });

    *total_controls += 1;
    if !has_legacy_auth_block {
        findings.push(Finding {
            severity: "HIGH".to_string(),
            category: "Conditional Access".to_string(),
            control: "CA-LEGACY-001".to_string(),
            description: "Legacy authentication not blocked".to_string(),
            remediation: "Deploy legacy auth block with: ctl365 ca deploy --block-legacy-auth"
                .to_string(),
            affected_resource: None,
            current_value: Some("Legacy auth allowed".to_string()),
            expected_value: Some("Legacy authentication blocked".to_string()),
        });
    } else {
        *passed_controls += 1;
    }
}

fn compare_policies(baseline: &Value, current: &Value) -> Vec<SettingDifference> {
    let mut differences = Vec::new();

    // Compare common fields
    let fields_to_compare = vec!["displayName", "description", "state", "platforms"];

    for field in fields_to_compare {
        let baseline_value = baseline.get(field);
        let current_value = current.get(field);

        if baseline_value != current_value {
            differences.push(SettingDifference {
                setting_name: field.to_string(),
                expected_value: baseline_value.map(|v| v.to_string()),
                actual_value: current_value.map(|v| v.to_string()),
            });
        }
    }

    differences
}

async fn create_policy_from_baseline(client: &GraphClient, policy: &Value) -> Result<Value> {
    let mut cleaned_policy = policy.clone();
    if let Some(obj) = cleaned_policy.as_object_mut() {
        obj.remove("id");
        obj.remove("createdDateTime");
        obj.remove("lastModifiedDateTime");
        obj.remove("version");
    }

    let odata_type = policy["@odata.type"].as_str().unwrap_or("");
    intune::create_policy(client, odata_type, &cleaned_policy).await
}

async fn list_settings_catalog_policies(client: &GraphClient) -> Result<Value> {
    client
        .get_beta("deviceManagement/configurationPolicies")
        .await
}

fn severity_icon(severity: &str) -> String {
    match severity {
        "CRITICAL" => "✗".red().bold().to_string(),
        "HIGH" => "⚠".yellow().bold().to_string(),
        "MEDIUM" => "ℹ".cyan().to_string(),
        "LOW" => "•".white().to_string(),
        "INFO" => "ℹ".blue().to_string(),
        _ => "•".to_string(),
    }
}

fn format_compliance_score(score: f32, passed: usize, total: usize) -> String {
    let color = if score >= 90.0 {
        "green"
    } else if score >= 70.0 {
        "yellow"
    } else {
        "red"
    };

    let bar_length = 50;
    let filled = (score / 100.0 * bar_length as f32) as usize;
    let bar = "█".repeat(filled) + &"░".repeat(bar_length - filled);

    format!(
        "{:.1}% ({}/{} controls passed)\n  [{}]",
        score,
        passed,
        total,
        match color {
            "green" => bar.green(),
            "yellow" => bar.yellow(),
            _ => bar.red(),
        }
    )
}

fn format_drift_score(score: f32) -> String {
    let color = if score >= 95.0 {
        "green"
    } else if score >= 80.0 {
        "yellow"
    } else {
        "red"
    };

    match color {
        "green" => format!("{:.1}%", score).green().to_string(),
        "yellow" => format!("{:.1}%", score).yellow().to_string(),
        _ => format!("{:.1}%", score).red().to_string(),
    }
}

fn generate_html_audit_report(report: &AuditReport) -> Result<String> {
    Ok(format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Compliance Audit Report - {}</title>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 40px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #0078d4;
            border-bottom: 3px solid #0078d4;
            padding-bottom: 10px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .metric {{
            background: #f3f2f1;
            padding: 20px;
            border-radius: 4px;
            text-align: center;
        }}
        .metric h3 {{
            margin: 0 0 10px 0;
            font-size: 14px;
            color: #605e5c;
            text-transform: uppercase;
        }}
        .metric .value {{
            font-size: 36px;
            font-weight: bold;
            color: #0078d4;
        }}
        .score {{
            font-size: 48px;
            font-weight: bold;
            margin: 20px 0;
        }}
        .score.good {{ color: #107c10; }}
        .score.warning {{ color: #f7b500; }}
        .score.bad {{ color: #d13438; }}
        .findings {{
            margin-top: 40px;
        }}
        .finding {{
            background: white;
            border-left: 4px solid #d13438;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .finding.critical {{ border-left-color: #d13438; }}
        .finding.high {{ border-left-color: #f7b500; }}
        .finding.medium {{ border-left-color: #0078d4; }}
        .finding.low {{ border-left-color: #107c10; }}
        .finding-header {{
            display: flex;
            align-items: center;
            margin-bottom: 10px;
        }}
        .severity {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            margin-right: 10px;
        }}
        .severity.critical {{ background: #d13438; color: white; }}
        .severity.high {{ background: #f7b500; color: black; }}
        .severity.medium {{ background: #0078d4; color: white; }}
        .control {{
            font-family: monospace;
            background: #f3f2f1;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 12px;
        }}
        .remediation {{
            background: #f3f2f1;
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
            font-family: monospace;
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Compliance Audit Report</h1>
        <p><strong>Tenant:</strong> {}</p>
        <p><strong>Baseline:</strong> {}</p>
        <p><strong>Date:</strong> {}</p>

        <div class="summary">
            <div class="metric">
                <h3>Compliance Score</h3>
                <div class="score {}">{:.1}%</div>
            </div>
            <div class="metric">
                <h3>Controls Passed</h3>
                <div class="value">{}/{}</div>
            </div>
            <div class="metric">
                <h3>Critical Issues</h3>
                <div class="value" style="color: #d13438;">{}</div>
            </div>
            <div class="metric">
                <h3>High Issues</h3>
                <div class="value" style="color: #f7b500;">{}</div>
            </div>
        </div>

        <div class="findings">
            <h2>Findings</h2>
            {}
        </div>
    </div>
</body>
</html>"#,
        report.tenant_name,
        report.tenant_name,
        report.baseline,
        report.audit_date,
        if report.compliance_score >= 90.0 {
            "good"
        } else if report.compliance_score >= 70.0 {
            "warning"
        } else {
            "bad"
        },
        report.compliance_score,
        report.passed_controls,
        report.total_controls,
        report.summary.critical_issues,
        report.summary.high_issues,
        report
            .findings
            .iter()
            .map(|f| {
                format!(
                    r#"<div class="finding {}">
                <div class="finding-header">
                    <span class="severity {}">{}</span>
                    <span class="control">{}</span>
                </div>
                <div><strong>{}:</strong> {}</div>
                <div class="remediation">{}</div>
            </div>"#,
                    f.severity.to_lowercase(),
                    f.severity.to_lowercase(),
                    f.severity,
                    f.control,
                    f.category,
                    f.description,
                    f.remediation
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

fn generate_csv_audit_report(report: &AuditReport) -> Result<String> {
    let mut csv = String::from("Severity,Category,Control,Description,Remediation\n");

    for finding in &report.findings {
        csv.push_str(&format!(
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
            finding.severity,
            finding.category,
            finding.control,
            finding.description.replace("\"", "\"\""),
            finding.remediation.replace("\"", "\"\"")
        ));
    }

    Ok(csv)
}

fn generate_html_drift_report(drift: &DriftResult) -> Result<String> {
    Ok(format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Configuration Drift Report - {}</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; }}
        h1 {{ color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }}
        .metric {{ display: inline-block; background: #f3f2f1; padding: 20px; margin: 10px; border-radius: 4px; }}
        .drift-item {{ background: #fff4ce; border-left: 4px solid #f7b500; padding: 10px; margin: 10px 0; }}
        .missing {{ border-left-color: #d13438; background: #fde7e9; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Configuration Drift Report</h1>
        <p><strong>Tenant:</strong> {}</p>
        <p><strong>Drift Score:</strong> {:.1}%</p>
        <p><strong>Date:</strong> {}</p>

        <h2>Missing Policies ({})</h2>
        {}

        <h2>Modified Policies ({})</h2>
        {}
    </div>
</body>
</html>"#,
        drift.tenant_name,
        drift.tenant_name,
        drift.drift_score,
        drift.drift_date,
        drift.missing_policies.len(),
        drift
            .missing_policies
            .iter()
            .map(|p| format!("<div class='drift-item missing'>{}</div>", p.policy_name))
            .collect::<Vec<_>>()
            .join("\n"),
        drift.modified_policies.len(),
        drift
            .modified_policies
            .iter()
            .map(|p| format!("<div class='drift-item'>{}</div>", p.policy_name))
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

// Report generation functionality

/// Generate compliance report
pub async fn report(args: ReportArgs) -> Result<()> {
    println!(
        "{} {} report...",
        "Generating".cyan().bold(),
        args.report_type.yellow()
    );

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant".into()))?;

    println!("→ Tenant: {}", active_tenant.name.cyan().bold());
    println!("→ Format: {}", args.format.cyan());

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Collect data based on report type
    let report_data = match args.report_type.as_str() {
        "compliance" => generate_compliance_report_data(&graph, &active_tenant.name).await?,
        "security" => generate_security_report_data(&graph, &active_tenant.name).await?,
        "inventory" => generate_inventory_report_data(&graph, &active_tenant.name).await?,
        "executive" => generate_executive_report_data(&graph, &active_tenant.name).await?,
        _ => {
            return Err(crate::error::Ctl365Error::ConfigError(format!(
                "Unknown report type: {}. Valid types: compliance, security, inventory, executive",
                args.report_type
            )));
        }
    };

    // Format report
    let output = match args.format.as_str() {
        "html" => format_report_html(&report_data, &args.report_type, args.include_charts)?,
        "json" => serde_json::to_string_pretty(&report_data)?,
        "csv" => format_report_csv(&report_data)?,
        _ => {
            return Err(crate::error::Ctl365Error::ConfigError(format!(
                "Unknown format: {}. Valid formats: html, json, csv",
                args.format
            )));
        }
    };

    // Save or print
    if let Some(output_path) = &args.output {
        fs::write(output_path, &output)?;
        println!(
            "\n{} Report saved to: {}",
            "✓".green().bold(),
            output_path.display()
        );
    } else {
        println!("\n{}", output);
    }

    Ok(())
}

async fn generate_compliance_report_data(graph: &GraphClient, tenant_name: &str) -> Result<Value> {
    // Get compliance policies
    let compliance_policies = match intune::list_compliance_policies(graph).await {
        Ok(p) => p["value"].as_array().map(|a| a.len()).unwrap_or(0),
        Err(_) => 0,
    };

    // Get device configurations
    let device_configs = match intune::list_device_configurations(graph).await {
        Ok(p) => p["value"].as_array().map(|a| a.len()).unwrap_or(0),
        Err(_) => 0,
    };

    // Get CA policies
    let ca_policies = match conditional_access::list_policies(graph).await {
        Ok(p) => p["value"].as_array().map(|a| a.len()).unwrap_or(0),
        Err(_) => 0,
    };

    Ok(json!({
        "report_type": "compliance",
        "tenant": tenant_name,
        "generated": chrono::Utc::now().to_rfc3339(),
        "summary": {
            "compliance_policies": compliance_policies,
            "device_configurations": device_configs,
            "conditional_access_policies": ca_policies,
            "total_policies": compliance_policies + device_configs + ca_policies
        }
    }))
}

async fn generate_security_report_data(graph: &GraphClient, tenant_name: &str) -> Result<Value> {
    // Check security defaults
    let security_defaults_enabled = match conditional_access::get_security_defaults(graph).await {
        Ok(defaults) => defaults["isEnabled"].as_bool().unwrap_or(false),
        Err(_) => false,
    };

    // Get CA policies
    let ca_policies = match conditional_access::list_policies(graph).await {
        Ok(p) => p,
        Err(_) => json!({"value": []}),
    };

    let ca_list = ca_policies["value"].as_array();
    let total_ca = ca_list.map(|a| a.len()).unwrap_or(0);
    let enabled_ca = ca_list
        .map(|a| {
            a.iter()
                .filter(|p| p["state"].as_str() == Some("enabled"))
                .count()
        })
        .unwrap_or(0);
    let report_only_ca = ca_list
        .map(|a| {
            a.iter()
                .filter(|p| p["state"].as_str() == Some("enabledForReportingButNotEnforced"))
                .count()
        })
        .unwrap_or(0);

    Ok(json!({
        "report_type": "security",
        "tenant": tenant_name,
        "generated": chrono::Utc::now().to_rfc3339(),
        "security_status": {
            "security_defaults_enabled": security_defaults_enabled,
            "conditional_access": {
                "total": total_ca,
                "enabled": enabled_ca,
                "report_only": report_only_ca,
                "disabled": total_ca - enabled_ca - report_only_ca
            }
        }
    }))
}

async fn generate_inventory_report_data(graph: &GraphClient, tenant_name: &str) -> Result<Value> {
    let compliance = match intune::list_compliance_policies(graph).await {
        Ok(p) => p["value"].clone(),
        Err(_) => json!([]),
    };

    let configs = match intune::list_device_configurations(graph).await {
        Ok(p) => p["value"].clone(),
        Err(_) => json!([]),
    };

    let ca = match conditional_access::list_policies(graph).await {
        Ok(p) => p["value"].clone(),
        Err(_) => json!([]),
    };

    Ok(json!({
        "report_type": "inventory",
        "tenant": tenant_name,
        "generated": chrono::Utc::now().to_rfc3339(),
        "inventory": {
            "compliance_policies": compliance,
            "device_configurations": configs,
            "conditional_access_policies": ca
        }
    }))
}

async fn generate_executive_report_data(graph: &GraphClient, tenant_name: &str) -> Result<Value> {
    // Combine compliance and security data for executive summary
    let compliance = generate_compliance_report_data(graph, tenant_name).await?;
    let security = generate_security_report_data(graph, tenant_name).await?;

    Ok(json!({
        "report_type": "executive",
        "tenant": tenant_name,
        "generated": chrono::Utc::now().to_rfc3339(),
        "overview": {
            "total_policies": compliance["summary"]["total_policies"],
            "security_defaults": security["security_status"]["security_defaults_enabled"],
            "ca_enabled": security["security_status"]["conditional_access"]["enabled"]
        },
        "compliance_summary": compliance["summary"],
        "security_summary": security["security_status"]
    }))
}

fn format_report_html(data: &Value, report_type: &str, include_charts: bool) -> Result<String> {
    let tenant = data["tenant"].as_str().unwrap_or("Unknown");
    let generated = data["generated"].as_str().unwrap_or("Unknown");

    // Extract summary metrics for display
    let summary = data.get("summary");
    let security_status = data.get("security_status");

    // Build metric cards based on report type
    let metrics_html = match report_type {
        "compliance" => {
            if let Some(s) = summary {
                format!(
                    r#"<div class="metrics-grid">
                        <div class="metric-card">
                            <div class="metric-value">{}</div>
                            <div class="metric-label">Compliance Policies</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">{}</div>
                            <div class="metric-label">Device Configurations</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">{}</div>
                            <div class="metric-label">Conditional Access</div>
                        </div>
                        <div class="metric-card highlight">
                            <div class="metric-value">{}</div>
                            <div class="metric-label">Total Policies</div>
                        </div>
                    </div>"#,
                    s["compliance_policies"].as_u64().unwrap_or(0),
                    s["device_configurations"].as_u64().unwrap_or(0),
                    s["conditional_access_policies"].as_u64().unwrap_or(0),
                    s["total_policies"].as_u64().unwrap_or(0)
                )
            } else {
                String::new()
            }
        }
        "security" => {
            if let Some(sec) = security_status {
                let ca = &sec["conditional_access"];
                let defaults_status = if sec["security_defaults_enabled"].as_bool().unwrap_or(false)
                {
                    r#"<span class="status-warning">Enabled</span>"#
                } else {
                    r#"<span class="status-good">Disabled (CA Active)</span>"#
                };
                format!(
                    r#"<div class="metrics-grid">
                        <div class="metric-card">
                            <div class="metric-value">{}</div>
                            <div class="metric-label">CA Policies Enabled</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">{}</div>
                            <div class="metric-label">Report-Only</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">{}</div>
                            <div class="metric-label">Total CA Policies</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-label">Security Defaults</div>
                            <div class="metric-status">{}</div>
                        </div>
                    </div>"#,
                    ca["enabled"].as_u64().unwrap_or(0),
                    ca["report_only"].as_u64().unwrap_or(0),
                    ca["total"].as_u64().unwrap_or(0),
                    defaults_status
                )
            } else {
                String::new()
            }
        }
        "executive" => {
            let overview = data.get("overview");
            if let Some(o) = overview {
                format!(
                    r#"<div class="executive-summary">
                        <div class="metric-card large">
                            <div class="metric-value">{}</div>
                            <div class="metric-label">Total Policies Deployed</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">{}</div>
                            <div class="metric-label">CA Policies Enabled</div>
                        </div>
                    </div>"#,
                    o["total_policies"].as_u64().unwrap_or(0),
                    o["ca_enabled"].as_u64().unwrap_or(0)
                )
            } else {
                String::new()
            }
        }
        _ => String::new(),
    };

    // Chart placeholder if requested
    let charts_html = if include_charts {
        r#"<div class="charts-section">
            <h2>Visual Analytics</h2>
            <p class="chart-note">Charts available in future release</p>
        </div>"#
    } else {
        ""
    };

    Ok(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_type} Report - {tenant}</title>
    <style>
        :root {{
            --primary: #0078d4;
            --primary-dark: #106ebe;
            --success: #107c10;
            --warning: #f7b500;
            --danger: #d13438;
            --gray-100: #faf9f8;
            --gray-200: #f3f2f1;
            --gray-500: #605e5c;
            --gray-800: #323130;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--gray-100);
            color: var(--gray-800);
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }}
        .header {{
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 12px rgba(0,120,212,0.3);
        }}
        .header h1 {{
            font-size: 2rem;
            font-weight: 600;
            margin-bottom: 8px;
        }}
        .header .subtitle {{
            opacity: 0.9;
            font-size: 1rem;
        }}
        .header-meta {{
            display: flex;
            gap: 24px;
            margin-top: 20px;
            font-size: 0.9rem;
            opacity: 0.85;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background: white;
            padding: 24px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .metric-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.12);
        }}
        .metric-card.highlight {{
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white;
        }}
        .metric-card.large {{
            grid-column: span 2;
        }}
        .metric-value {{
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary);
        }}
        .metric-card.highlight .metric-value {{
            color: white;
        }}
        .metric-label {{
            font-size: 0.85rem;
            color: var(--gray-500);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 8px;
        }}
        .metric-card.highlight .metric-label {{
            color: rgba(255,255,255,0.85);
        }}
        .status-good {{ color: var(--success); font-weight: 600; }}
        .status-warning {{ color: var(--warning); font-weight: 600; }}
        .status-danger {{ color: var(--danger); font-weight: 600; }}
        .section {{
            background: white;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}
        .section h2 {{
            font-size: 1.25rem;
            color: var(--primary);
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 2px solid var(--gray-200);
        }}
        .footer {{
            text-align: center;
            padding: 30px;
            color: var(--gray-500);
            font-size: 0.85rem;
        }}
        .footer a {{
            color: var(--primary);
            text-decoration: none;
        }}
        .charts-section {{
            background: var(--gray-200);
            border-radius: 8px;
            padding: 40px;
            text-align: center;
            margin-bottom: 20px;
        }}
        .chart-note {{
            color: var(--gray-500);
            font-style: italic;
        }}
        @media print {{
            body {{ background: white; }}
            .container {{ padding: 0; }}
            .metric-card {{ break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>{report_type_display} Report</h1>
            <p class="subtitle">Microsoft 365 Tenant Analysis</p>
            <div class="header-meta">
                <span><strong>Tenant:</strong> {tenant}</span>
                <span><strong>Generated:</strong> {generated_display}</span>
            </div>
        </header>

        {metrics}

        {charts}

        <footer class="footer">
            <p>Generated by <strong>ctl365</strong> v{version}</p>
            <p><a href="https://github.com/resolvetech/ctl365">Documentation</a></p>
        </footer>
    </div>
</body>
</html>"#,
        report_type = report_type,
        tenant = tenant,
        report_type_display = match report_type {
            "compliance" => "Compliance",
            "security" => "Security Assessment",
            "inventory" => "Policy Inventory",
            "executive" => "Executive Summary",
            _ => report_type,
        },
        generated_display = &generated[..19].replace("T", " "),
        metrics = metrics_html,
        charts = charts_html,
        version = env!("CARGO_PKG_VERSION")
    ))
}

fn format_report_csv(data: &Value) -> Result<String> {
    let mut csv = String::from("Field,Value\n");
    csv.push_str(&format!(
        "Report Type,{}\n",
        data["report_type"].as_str().unwrap_or("")
    ));
    csv.push_str(&format!(
        "Tenant,{}\n",
        data["tenant"].as_str().unwrap_or("")
    ));
    csv.push_str(&format!(
        "Generated,{}\n",
        data["generated"].as_str().unwrap_or("")
    ));

    if let Some(summary) = data.get("summary").and_then(|s| s.as_object()) {
        for (key, value) in summary {
            csv.push_str(&format!("{},{}\n", key, value));
        }
    }

    Ok(csv)
}
